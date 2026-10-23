from enum import Enum
from typing import Set, Dict


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class Permission(str, Enum):
    # Agent & Tool Management
    AGENT_READ = "agent:read"
    AGENT_REGISTER = "agent:register"
    AGENT_REVOKE = "agent:revoke"
    
    # Policy Management
    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"
    POLICY_ROLLBACK = "policy:rollback"
    
    # Audit & Incidents
    AUDIT_READ = "audit:read"
    AUDIT_VERIFY = "audit:verify"
    INCIDENT_READ = "incident:read"
    INCIDENT_WRITE = "incident:write"
    
    # System Administration
    SYSTEM_ADMIN = "system:admin"


ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {p for p in Permission},
    Role.ANALYST: {
        Permission.AGENT_READ,
        Permission.POLICY_READ,
        Permission.AUDIT_READ,
        Permission.AUDIT_VERIFY,
        Permission.INCIDENT_READ,
        Permission.INCIDENT_WRITE,
    },
    Role.AUDITOR: {
        Permission.AGENT_READ,
        Permission.POLICY_READ,
        Permission.AUDIT_READ,
        Permission.AUDIT_VERIFY,
        Permission.INCIDENT_READ,
    },
    Role.VIEWER: {
        Permission.AGENT_READ,
        Permission.POLICY_READ,
        Permission.AUDIT_READ,
        Permission.INCIDENT_READ,
    },
}


def has_permission(role: str, permission: Permission) -> bool:
    try:
        r = Role(role.lower())
        return permission in ROLE_PERMISSIONS.get(r, set())
    except ValueError:
        return False
