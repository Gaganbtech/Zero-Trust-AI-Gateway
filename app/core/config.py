import os
import secrets
from typing import List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Core Application Settings
    ENVIRONMENT: str = Field(default="development", description="Environment: development, test, staging, production")
    APP_NAME: str = "Zero-Trust AI Runtime Gateway"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = Field(
        default="sqlite:///./gateway.db",
        description="SQLAlchemy database URL (PostgreSQL or SQLite)"
    )
    DATABASE_ECHO: bool = False

    @property
    def database_path(self) -> str:
        if self.DATABASE_URL.startswith("sqlite:///"):
            return self.DATABASE_URL[len("sqlite:///"):]
        return self.DATABASE_URL

    @database_path.setter
    def database_path(self, val: str):
        if not val.startswith("sqlite://") and not val.startswith("postgresql://"):
            self.DATABASE_URL = f"sqlite:///{val}"
        else:
            self.DATABASE_URL = val

    # Security & Cryptography
    SECRET_KEY: str = Field(
        default="insecure-dev-secret-key-change-in-production-min32chars!",
        description="Secret key for signing user sessions and JWTs"
    )
    WORKLOAD_SIGNING_SECRET: str = Field(
        default="insecure-dev-workload-secret-key-change-in-production-min32chars!",
        description="Secret key for agent workload identity JWT verification"
    )
    AUDIT_CHAIN_SALT: str = Field(
        default="insecure-dev-audit-salt-change-in-production-min32chars!",
        description="Cryptographic salt for tamper-evident audit hash chaining"
    )
    GATEWAY_AGENT_TOKEN: str = Field(
        default="dev-agent-token-change-me",
        description="Legacy token for backward compatibility in dev mode"
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 60
    WORKLOAD_TOKEN_EXPIRATION_MINUTES: int = 15

    # OPA Policy Engine
    OPA_URL: str = Field(
        default="http://127.0.0.1:8181/v1/data/ai_gateway/allow",
        description="Open Policy Agent decision URL"
    )
    OPA_TIMEOUT_SECONDS: float = Field(default=0.5, ge=0.01, le=5.0)
    OPA_FAIL_CLOSED: bool = Field(
        default=False,
        description="If True, gateway fails closed when OPA is unreachable. Always True in production."
    )

    # Network & SSRF Defenses
    ALLOWED_OUTBOUND_DOMAINS: List[str] = Field(
        default_factory=lambda: [
            "api.weather.example",
            "api.github.com",
            "httpbin.org",
            "synthetic.destinations.internal"
        ]
    )
    OUTBOUND_HTTP_TIMEOUT_SECONDS: float = Field(default=3.0, ge=0.1, le=30.0)
    OUTBOUND_MAX_RESPONSE_BYTES: int = Field(default=1024 * 512, ge=1024, le=10 * 1024 * 1024)

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=120, ge=10, le=10000)

    # CORS
    CORS_ORIGINS: List[str] = Field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ]
    )

    # Validation
    @field_validator("OPA_FAIL_CLOSED", mode="before")
    @classmethod
    def validate_fail_closed(cls, v, info):
        # In production, OPA must always fail closed
        env = os.getenv("ENVIRONMENT", "development").lower()
        if env == "production":
            return True
        if isinstance(v, str):
            return v.lower() in ("1", "true", "yes")
        return bool(v)

    def validate_production_readiness(self):
        """Enforces zero-trust production constraints on startup."""
        if self.ENVIRONMENT.lower() == "production":
            insecure_defaults = [
                "insecure-dev-secret-key-change-in-production-min32chars!",
                "insecure-dev-workload-secret-key-change-in-production-min32chars!",
                "insecure-dev-audit-salt-change-in-production-min32chars!",
                "dev-agent-token-change-me",
            ]
            if any(s in [self.SECRET_KEY, self.WORKLOAD_SIGNING_SECRET, self.AUDIT_CHAIN_SALT] for s in insecure_defaults):
                raise ValueError("FATAL: Insecure default secrets detected in production environment!")
            if len(self.SECRET_KEY) < 32 or len(self.WORKLOAD_SIGNING_SECRET) < 32:
                raise ValueError("FATAL: Production secrets must be at least 32 characters long!")
            if not self.OPA_FAIL_CLOSED:
                raise ValueError("FATAL: OPA_FAIL_CLOSED must be enabled in production!")
            if "sqlite" in self.DATABASE_URL.lower():
                raise ValueError("FATAL: SQLite is prohibited in production; use PostgreSQL!")


settings = Settings()
