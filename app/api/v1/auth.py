from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.database.models import User, AgentRegistryItem
from app.schemas.gateway import UserLoginRequest, WorkloadTokenIssueRequest
from app.auth.security import (
    verify_password,
    create_access_token,
    create_workload_token,
)
from app.auth.dependencies import get_current_user
from app.auth.rbac import Role, ROLE_PERMISSIONS
from app.core.config import settings

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication & Identity"])


@router.post("/login", summary="Human Operator Login")
async def login(
    payload: UserLoginRequest,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Authenticates a security operator and issues an HttpOnly session cookie
    and bearer access token.
    """
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password."
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account deactivated.")

    token = create_access_token({"sub": user.id, "role": user.role, "username": user.username})

    # Set secure HttpOnly cookie
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=(settings.ENVIRONMENT == "production"),
        max_age=settings.JWT_EXPIRATION_MINUTES * 60,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
        }
    }


@router.post("/token", summary="Issue Agent Workload Identity Token")
async def issue_workload_token(
    payload: WorkloadTokenIssueRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Issues a cryptographically signed workload token for an authorized agent.
    Requires operator authentication.
    """
    if current_user.role not in (Role.ADMIN.value, Role.ANALYST.value):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators or analysts can issue workload identity tokens."
        )

    agent = db.query(AgentRegistryItem).filter(AgentRegistryItem.id == payload.agent_id).first()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found in registry")
    if agent.status != "ACTIVE":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Cannot issue token for {agent.status} agent")

    scopes = payload.scopes if payload.scopes else agent.scopes
    allowed_tools = payload.allowed_tools if payload.allowed_tools else agent.allowed_tools

    token = create_workload_token(
        agent_id=agent.id,
        tenant_id=agent.tenant_id,
        scopes=scopes,
        allowed_tools=allowed_tools,
    )

    return {
        "workload_token": token,
        "agent_id": agent.id,
        "tenant_id": agent.tenant_id,
        "scopes": scopes,
        "allowed_tools": allowed_tools,
        "expires_in_minutes": settings.WORKLOAD_TOKEN_EXPIRATION_MINUTES,
        "token_type": "bearer"
    }


@router.get("/me", summary="Current User Profile")
async def get_me(current_user: User = Depends(get_current_user)):
    """Returns profile and RBAC permissions of currently authenticated user."""
    role_enum = Role(current_user.role)
    perms = [p.value for p in ROLE_PERMISSIONS.get(role_enum, set())]
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "permissions": perms
    }


@router.post("/logout", summary="Logout Operator")
async def logout(response: Response):
    response.delete_cookie(key="session_token")
    return {"message": "Successfully logged out."}
