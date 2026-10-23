import secrets
from typing import Optional, List, Callable
from fastapi import Depends, HTTPException, Header, Cookie, status
from sqlalchemy.orm import Session
from app.core.config import settings
from app.database.session import get_db
from app.database.models import User, AgentRegistryItem
from app.auth.security import decode_access_token, verify_workload_token
from app.auth.rbac import Role, Permission, has_permission
from app.auth.workload import VerifiedWorkload


async def get_current_user(
    authorization: Optional[str] = Header(None),
    session_token: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
) -> User:
    """
    Extracts and verifies human user session token from either Authorization header or HttpOnly cookie.
    """
    token = None
    if authorization:
        parts = authorization.split(" ")
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
    elif session_token:
        token = session_token

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid session token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account not found")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is deactivated")

    return user


def require_roles(allowed_roles: List[Role]) -> Callable:
    """FastAPI dependency to enforce server-side RBAC on endpoints."""
    allowed_role_strs = [r.value for r in allowed_roles]

    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_role_strs:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required one of: {allowed_role_strs}. Your role: {current_user.role}"
            )
        return current_user

    return role_checker


def require_permission(permission: Permission) -> Callable:
    """FastAPI dependency to enforce specific permissions."""
    async def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if not has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Missing required permission: {permission.value}"
            )
        return current_user

    return permission_checker


async def get_current_workload(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> VerifiedWorkload:
    """
    Zero-Trust Workload Identity Verifier for AI Agents.
    Never trusts `agent_id` or `tenant_id` from the request body.
    Requires signed workload token in Authorization: Bearer <token>.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Workload identity credentials required in Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization format. Must be 'Bearer <workload-jwt>'."
        )

    token = parts[1]

    # Check for development fallback token (strictly controlled by environment)
    if settings.ENVIRONMENT != "production" and secrets.compare_digest(token, settings.GATEWAY_AGENT_TOKEN):
        return VerifiedWorkload(
            agent_id="demo-agent",
            tenant_id="tenant-alpha",
            scopes=["customer:read", "weather:read", "http:egress"],
            allowed_tools=["db_query", "weather", "safe_http"],
            issuer="zero-trust-gateway-dev-mock",
            is_development_fallback=True
        )

    # Production cryptographic JWT workload verification
    try:
        claims = verify_workload_token(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Workload identity verification failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    agent_id = claims["sub"]
    tenant_id = claims.get("tenant_id", "default-tenant")
    scopes = claims.get("scopes", [])
    allowed_tools = claims.get("allowed_tools", [])

    # Verify agent registry status
    agent_record = db.query(AgentRegistryItem).filter(AgentRegistryItem.id == agent_id).first()
    if agent_record:
        if agent_record.status == "SUSPENDED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Agent '{agent_id}' is suspended by security policy."
            )
        if agent_record.status == "REVOKED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Agent '{agent_id}' credentials have been permanently revoked."
            )

    return VerifiedWorkload(
        agent_id=agent_id,
        tenant_id=tenant_id,
        scopes=scopes,
        allowed_tools=allowed_tools,
        issuer=claims.get("iss", "zero-trust-gateway-auth-authority"),
        is_development_fallback=False
    )
