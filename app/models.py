from typing import Any
from pydantic import BaseModel, Field

class AgentRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)

class ActionRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=100)
    tool: str = Field(min_length=1, max_length=100)
    operation: str = Field(min_length=1, max_length=20)
    table: str | None = None
    sql: str | None = Field(default=None, max_length=2000)
    destination: str = Field(min_length=1, max_length=500)
    method: str = Field(min_length=1, max_length=20)
    args: dict[str, Any] = Field(default_factory=dict)

class DLPRequest(BaseModel):
    text: str = Field(max_length=10000)
