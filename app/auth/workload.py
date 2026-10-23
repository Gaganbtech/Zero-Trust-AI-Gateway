from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class VerifiedWorkload:
    agent_id: str
    tenant_id: str
    scopes: List[str] = field(default_factory=list)
    allowed_tools: List[str] = field(default_factory=list)
    issuer: str = "zero-trust-gateway-auth-authority"
    is_development_fallback: bool = False

    def has_scope(self, scope: str) -> bool:
        return "*" in self.scopes or scope in self.scopes

    def is_tool_allowed(self, tool_name: str) -> bool:
        return "*" in self.allowed_tools or tool_name in self.allowed_tools
