from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentPromptRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000, description="User prompt or instruction for AI agent")
    tenant_id: Optional[str] = Field(default="tenant-alpha", max_length=100)


class ActionRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=100)
    tool: str = Field(min_length=1, max_length=100)
    operation: str = Field(min_length=1, max_length=50)
    table: Optional[str] = Field(default=None, max_length=100)
    resource: Optional[str] = Field(default=None, max_length=200)
    sql: Optional[str] = Field(default=None, max_length=2000)
    destination: str = Field(min_length=1, max_length=500)
    method: str = Field(min_length=1, max_length=20)
    args: Dict[str, Any] = Field(default_factory=dict)


class PromptScanRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=10000)


class DLPRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20000)
    action: Optional[str] = Field(default="REDACT", pattern="^(ALLOW|REDACT|BLOCK)$")


class UserLoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=200)


class WorkloadTokenIssueRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=100)
    tenant_id: str = Field(min_length=1, max_length=100)
    scopes: Optional[List[str]] = Field(default_factory=list)
    allowed_tools: Optional[List[str]] = Field(default_factory=list)


class IncidentNoteRequest(BaseModel):
    notes: str = Field(min_length=1, max_length=4000)


class IncidentStatusRequest(BaseModel):
    status: str = Field(pattern="^(OPEN|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$")


class PolicyValidateRequest(BaseModel):
    rego_code: str = Field(min_length=10)
