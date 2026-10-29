from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class MCPJsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Union[str, int]] = 1
    method: str
    params: Optional[Dict[str, Any]] = Field(default_factory=dict)


class MCPJsonRpcError(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


class MCPJsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Union[str, int]] = 1
    result: Optional[Any] = None
    error: Optional[MCPJsonRpcError] = None


class MCPToolSchema(BaseModel):
    name: str
    description: str
    inputSchema: Dict[str, Any]
    zero_trust_policy: Dict[str, Any]


class MCPToolTestRequest(BaseModel):
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    agent_id: str = "demo-agent"
    tenant_id: str = "tenant-alpha"
