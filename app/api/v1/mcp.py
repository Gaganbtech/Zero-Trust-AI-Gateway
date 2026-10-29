from typing import Any, Dict, List
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.mcp.schemas import (
    MCPJsonRpcRequest,
    MCPJsonRpcResponse,
    MCPToolSchema,
    MCPToolTestRequest
)
from app.mcp.server import mcp_server, MCP_TOOLS

router = APIRouter(prefix="/api/v1/mcp", tags=["Model Context Protocol (MCP) Gateway"])


@router.post("", summary="Model Context Protocol (MCP) JSON-RPC 2.0 Endpoint")
async def mcp_json_rpc(
    request_body: MCPJsonRpcRequest,
    request: Request,
    db: Session = Depends(get_db)
) -> MCPJsonRpcResponse:
    """
    Zero-Trust Model Context Protocol (MCP) Server Endpoint.
    Implements standard JSON-RPC 2.0 protocol for LLM agents, Claude Desktop,
    and client SDKs connecting to gateway-mediated tools and prompts.
    """
    correlation_id = getattr(request.state, "correlation_id", None)
    return await mcp_server.handle_request(
        request=request_body,
        db=db,
        workload=None,
        correlation_id=correlation_id
    )


@router.get("/tools", summary="List Registered MCP Tools and Zero-Trust Policies")
async def list_mcp_tools():
    """Returns catalog of tools registered in the MCP gateway along with their schema and security policies."""
    return [
        {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.inputSchema,
            "zero_trust_policy": t.zero_trust_policy
        }
        for t in MCP_TOOLS
    ]


@router.post("/test-call", summary="Test MCP Tool Execution via Operator Sandbox")
async def test_mcp_call(
    payload: MCPToolTestRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Allows security operators to test individual MCP tool calls through
    the zero-trust gateway pipeline directly from the dashboard.
    """
    correlation_id = getattr(request.state, "correlation_id", None)
    req = MCPJsonRpcRequest(
        id="test_sandbox",
        method="tools/call",
        params={
            "name": payload.tool_name,
            "arguments": payload.arguments,
            "agent_id": payload.agent_id,
            "tenant_id": payload.tenant_id
        }
    )
    resp = await mcp_server.handle_request(req, db=db, correlation_id=correlation_id)
    return resp.model_dump()
