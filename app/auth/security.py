import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from app.core.config import settings


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token for human dashboard users."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
    to_encode.update({"exp": expire, "iat": now, "type": "human_session"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a human JWT access token."""
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["exp", "iat", "sub"]}
    )


def create_workload_token(
    agent_id: str,
    tenant_id: str,
    scopes: list[str],
    allowed_tools: list[str],
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a cryptographically signed workload identity token for an AI agent."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.WORKLOAD_TOKEN_EXPIRATION_MINUTES)

    payload = {
        "iss": "zero-trust-gateway-auth-authority",
        "sub": agent_id,
        "aud": "zero-trust-gateway-api",
        "tenant_id": tenant_id,
        "scopes": scopes,
        "allowed_tools": allowed_tools,
        "iat": now,
        "exp": expire,
        "type": "workload_identity"
    }
    return jwt.encode(payload, settings.WORKLOAD_SIGNING_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_workload_token(token: str) -> Dict[str, Any]:
    """
    Cryptographically verify an AI agent workload identity token.
    Fails closed if expired, forged, or missing required workload claims.
    """
    return jwt.decode(
        token,
        settings.WORKLOAD_SIGNING_SECRET,
        algorithms=[settings.JWT_ALGORITHM],
        audience="zero-trust-gateway-api",
        issuer="zero-trust-gateway-auth-authority",
        options={"require": ["exp", "iat", "sub", "iss", "aud", "tenant_id", "scopes"]}
    )
