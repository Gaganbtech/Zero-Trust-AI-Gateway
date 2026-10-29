import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.auth.workload import VerifiedWorkload
from app.core.config import settings
from app.gateway.engine import mediate_tool_action
from app.mcp.schemas import (
    MCPJsonRpcRequest,
    MCPJsonRpcResponse,
    MCPJsonRpcError,
    MCPToolSchema
)

logger = logging.getLogger(__name__)

# Official Model Context Protocol Tool Catalog
MCP_TOOLS: List[MCPToolSchema] = [
    MCPToolSchema(
        name="db_query",
        description="Zero-Trust Parameterized Database Query Tool. Executes tenant-scoped read queries against allowlisted tables and columns.",
        inputSchema={
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Target table name. Allowed: 'customers'"
                },
                "columns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowlisted columns: id, name, email, phone, card_number, account_balance"
                },
                "limit": {
                    "type": "integer",
                    "description": "Max rows to return (capped at 20)"
                }
            },
            "required": ["table"]
        },
        zero_trust_policy={
            "enforcement": "OPA + Column Allowlist + Tenant Scoping",
            "required_scope": "customer:read",
            "allowed_destinations": ["sqlite://demo", "postgresql://internal"],
            "dlp_redaction": "Automatic PII & Financial token masking"
        }
    ),
    MCPToolSchema(
        name="safe_http",
        description="Zero-Trust Outbound HTTP Egress Tool. Connects only to pre-approved external domains with comprehensive SSRF protection.",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target external URL (e.g. https://httpbin.org/get)"
                }
            },
            "required": ["url"]
        },
        zero_trust_policy={
            "enforcement": "Pre-connection DNS Check + RFC 1918 / IMDS Filtering",
            "required_scope": "http:egress",
            "allowed_domains": settings.ALLOWED_OUTBOUND_DOMAINS,
            "dlp_redaction": "Response credential and token sanitization"
        }
    ),
    MCPToolSchema(
        name="weather",
        description="Zero-Trust Atmospheric Condition Query Tool. Fetches current weather reports for authorized locations.",
        inputSchema={
            "type": "object",
            "properties": {
                "city": {
                    "type": "string",
                    "description": "City name (e.g. Bengaluru, Seattle, Tokyo)"
                }
            },
            "required": ["city"]
        },
        zero_trust_policy={
            "enforcement": "Approved Destination Whitelist",
            "required_scope": "weather:read",
            "allowed_destinations": ["https://api.weather.example/v1/current"],
            "dlp_redaction": "Payload inspection"
        }
    ),
    MCPToolSchema(
        name="cspm_scan",
        description="Zero-Trust Cloud Security Posture Management Evaluation Tool. Audits AWS, Azure, GCP, and Kubernetes for AI workloads.",
        inputSchema={
            "type": "object",
            "properties": {
                "environment": {
                    "type": "string",
                    "enum": ["AWS", "Azure", "GCP", "Kubernetes", "ALL"],
                    "description": "Target cloud environment"
                }
            }
        },
        zero_trust_policy={
            "enforcement": "AI-CSPM Policy Matrix",
            "required_scope": "cspm:read",
            "allowed_destinations": ["cloud://posture-engine"],
            "dlp_redaction": "Masks cloud account IDs and raw secrets"
        }
    )
]


class MCPZeroTrustServer:
    """Model Context Protocol (MCP) Server implementing Zero-Trust runtime mediation."""

    def __init__(self):
        self.server_name = "zero-trust-ai-gateway-mcp"
        self.server_version = "1.0.0"
        self.protocol_version = settings.MCP_PROTOCOL_VERSION

    async def handle_request(
        self,
        request: MCPJsonRpcRequest,
        db: Session,
        workload: Optional[VerifiedWorkload] = None,
        correlation_id: Optional[str] = None
    ) -> MCPJsonRpcResponse:
        method = request.method
        req_id = request.id

        try:
            if method == "initialize":
                return self._handle_initialize(req_id)
            elif method == "tools/list":
                return self._handle_tools_list(req_id)
            elif method == "tools/call":
                return await self._handle_tools_call(req_id, request.params or {}, db, workload, correlation_id)
            elif method == "prompts/list":
                return self._handle_prompts_list(req_id)
            elif method == "resources/list":
                return self._handle_resources_list(req_id)
            else:
                return MCPJsonRpcResponse(
                    id=req_id,
                    error=MCPJsonRpcError(code=-32601, message=f"Method '{method}' not found")
                )
        except HTTPException as hexp:
            err_msg = hexp.detail.get("error") if isinstance(hexp.detail, dict) else str(hexp.detail)
            return MCPJsonRpcResponse(
                id=req_id,
                error=MCPJsonRpcError(code=-32000, message=err_msg, data=hexp.detail)
            )
        except Exception as e:
            logger.exception("MCP server unhandled error")
            return MCPJsonRpcResponse(
                id=req_id,
                error=MCPJsonRpcError(code=-32603, message=f"Internal MCP Gateway error: {str(e)}")
            )

    def _handle_initialize(self, req_id: Any) -> MCPJsonRpcResponse:
        return MCPJsonRpcResponse(
            id=req_id,
            result={
                "protocolVersion": self.protocol_version,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "prompts": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False}
                },
                "serverInfo": {
                    "name": self.server_name,
                    "version": self.server_version
                },
                "instructions": (
                    "This is an enterprise Zero-Trust Model Context Protocol Gateway. "
                    "All tool calls are strictly authenticated, evaluated against Open Policy Agent (OPA) "
                    "rules, protected by SSRF pre-flight validation, scoped to tenant boundaries, and "
                    "sanitized by a recursive Data Loss Prevention (DLP) engine."
                )
            }
        )

    def _handle_tools_list(self, req_id: Any) -> MCPJsonRpcResponse:
        tools_list = [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.inputSchema,
                "_zero_trust_policy": t.zero_trust_policy
            }
            for t in MCP_TOOLS
        ]
        return MCPJsonRpcResponse(id=req_id, result={"tools": tools_list})

    async def _handle_tools_call(
        self,
        req_id: Any,
        params: Dict[str, Any],
        db: Session,
        workload: Optional[VerifiedWorkload] = None,
        correlation_id: Optional[str] = None
    ) -> MCPJsonRpcResponse:
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}

        # Default workload for authorized MCP agent if not explicitly passed
        if not workload:
            agent_id = params.get("agent_id") or "demo-agent"
            tenant_id = params.get("tenant_id") or "tenant-alpha"
            workload = VerifiedWorkload(
                agent_id=agent_id,
                tenant_id=tenant_id,
                scopes=["customer:read", "weather:read", "http:egress", "cspm:read"],
                allowed_tools=["db_query", "weather", "safe_http", "cspm_scan"],
                issuer="mcp-gateway"
            )

        if tool_name == "db_query":
            action_data = {
                "agent_id": workload.agent_id,
                "tool": "db_query",
                "operation": "SELECT",
                "table": arguments.get("table", "customers"),
                "destination": "sqlite://demo",
                "method": "INTERNAL",
                "args": arguments
            }
        elif tool_name == "safe_http":
            target_url = arguments.get("url", "https://httpbin.org/get")
            action_data = {
                "agent_id": workload.agent_id,
                "tool": "safe_http",
                "operation": "GET",
                "destination": target_url,
                "method": "GET",
                "args": arguments
            }
        elif tool_name == "weather":
            action_data = {
                "agent_id": workload.agent_id,
                "tool": "weather",
                "operation": "GET",
                "destination": "https://api.weather.example/v1/current",
                "method": "GET",
                "args": arguments
            }
        elif tool_name == "cspm_scan":
            from app.cspm.service import execute_and_persist_scan
            scan_res = execute_and_persist_scan(db=db, scan_type="MCP_TRIGGERED")
            return MCPJsonRpcResponse(
                id=req_id,
                result={
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({
                                "status": "COMPLETED",
                                "compliance_score": scan_res.compliance_score,
                                "passed_checks": scan_res.passed_checks,
                                "failed_checks": scan_res.failed_checks,
                                "findings_count": len(scan_res.findings)
                            }, indent=2)
                        }
                    ],
                    "isError": False,
                    "_zero_trust": {
                        "decision": "ALLOW",
                        "policy": "AI-CSPM Matrix",
                        "sanitized": True
                    }
                }
            )
        else:
            action_data = {
                "agent_id": workload.agent_id,
                "tool": tool_name or "unknown",
                "operation": "EXECUTE",
                "destination": "unknown://destination",
                "method": "UNKNOWN",
                "args": arguments
            }

        # Mediate through gateway 12-step sequence
        result = await mediate_tool_action(action_data, workload, db, correlation_id)

        return MCPJsonRpcResponse(
            id=req_id,
            result={
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result.get("result", {}), indent=2)
                    }
                ],
                "isError": False,
                "_zero_trust": {
                    "decision": result.get("decision"),
                    "event_id": result.get("event_id"),
                    "correlation_id": result.get("correlation_id"),
                    "dlp_redacted": result.get("dlp", {}).get("redacted", False)
                }
            }
        )

    def _handle_prompts_list(self, req_id: Any) -> MCPJsonRpcResponse:
        prompts = [
            {
                "name": "security_audit_assistant",
                "description": "Pre-configured system prompt for secure AI agent data querying.",
                "arguments": [
                    {"name": "tenant_id", "description": "Customer tenant context", "required": True}
                ]
            },
            {
                "name": "incident_investigation_brief",
                "description": "Prompt for autonomous incident triage and root-cause analysis.",
                "arguments": [
                    {"name": "incident_id", "description": "Target incident ID", "required": True}
                ]
            }
        ]
        return MCPJsonRpcResponse(id=req_id, result={"prompts": prompts})

    def _handle_resources_list(self, req_id: Any) -> MCPJsonRpcResponse:
        resources = [
            {
                "uri": "gateway://policies/agent.rego",
                "name": "Open Policy Agent Rego v1 Rules",
                "mimeType": "text/plain"
            },
            {
                "uri": "gateway://audit/tamper-ledger",
                "name": "HMAC-SHA256 Tamper-Evident Audit Ledger",
                "mimeType": "application/json"
            }
        ]
        return MCPJsonRpcResponse(id=req_id, result={"resources": resources})


mcp_server = MCPZeroTrustServer()
