from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.database.models import AgentRegistryItem
from app.schemas.gateway import ActionRequest, AgentPromptRequest
from app.auth.dependencies import get_current_workload, get_current_user
from app.auth.workload import VerifiedWorkload
from app.gateway.engine import mediate_tool_action
from app.scanners.prompt import scan_prompt
from app.audit.service import record_security_event

router = APIRouter(prefix="/api/v1/agents", tags=["Agent Registry & Execution"])


@router.get("", summary="List Registered Agents")
async def list_agents(
    db: Session = Depends(get_db)
):
    """Returns inventory of registered AI agents, statuses, and assigned tool scopes."""
    agents = db.query(AgentRegistryItem).all()
    return [
        {
            "id": a.id,
            "name": a.name,
            "tenant_id": a.tenant_id,
            "description": a.description,
            "status": a.status,
            "allowed_tools": a.allowed_tools,
            "scopes": a.scopes,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        }
        for a in agents
    ]


@router.get("/{agent_id}", summary="Get Agent Details")
async def get_agent(
    agent_id: str,
    db: Session = Depends(get_db)
):
    agent = db.query(AgentRegistryItem).filter(AgentRegistryItem.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return {
        "id": agent.id,
        "name": agent.name,
        "tenant_id": agent.tenant_id,
        "description": agent.description,
        "status": agent.status,
        "allowed_tools": agent.allowed_tools,
        "scopes": agent.scopes,
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
    }


@router.post("/{agent_id}/actions", summary="Execute Mediated Tool Action")
async def execute_agent_action(
    agent_id: str,
    action: ActionRequest,
    request: Request,
    workload: VerifiedWorkload = Depends(get_current_workload),
    db: Session = Depends(get_db)
):
    """
    Primary Zero-Trust Gateway Enforcement Boundary:
    Executes protected tool action after full workload authentication, schema validation,
    destination verification, OPA policy evaluation, execution guard, and DLP redaction.
    """
    correlation_id = getattr(request.state, "correlation_id", None)
    
    # Strictly enforce that path parameter matches verified workload identity
    if agent_id != workload.agent_id:
        record_security_event(
            agent_id=workload.agent_id,
            tenant_id=workload.tenant_id,
            tool=action.tool,
            operation=action.operation,
            decision="BLOCK",
            reason="agent_path_impersonation",
            destination=action.destination,
            correlation_id=correlation_id,
            risk_level="CRITICAL",
            db=db
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="URL agent parameter does not match verified workload identity token."
        )

    # Convert request to dictionary
    action_dict = action.model_dump()
    return await mediate_tool_action(action_dict, workload, db, correlation_id)


@router.post("/{agent_id}/prompt", summary="Run Local Deterministic Demo Agent")
async def run_agent_prompt(
    agent_id: str,
    payload: AgentPromptRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Local Deterministic AI Agent integration:
    1. Runs modular prompt injection & adversarial heuristics scan.
    2. Constructs authorized tool request.
    3. Executes request through the zero-trust runtime security gateway.
    """
    correlation_id = getattr(request.state, "correlation_id", None)
    prompt = payload.prompt

    # Step 1: Input & Prompt Injection Scanner
    scan_result = scan_prompt(prompt)
    if scan_result.is_flagged:
        event = record_security_event(
            agent_id=agent_id,
            tenant_id=payload.tenant_id or "tenant-alpha",
            tool="prompt_scan",
            operation="PROMPT",
            decision="BLOCK",
            reason=scan_result.reason,
            destination="agent://input",
            correlation_id=correlation_id,
            prompt_flagged=True,
            risk_level="HIGH",
            metadata={
                "prompt_length": len(prompt),
                "category": scan_result.category,
                "confidence": scan_result.confidence,
                "matched_patterns": scan_result.matched_patterns
            },
            db=db
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "Prompt blocked by input security policy",
                "event_id": event["event_id"],
                "reason": scan_result.reason,
                "category": scan_result.category,
                "confidence": scan_result.confidence
            }
        )

    # Step 2: Deterministic demo agent intent resolution
    prompt_lower = prompt.lower()
    workload = VerifiedWorkload(
        agent_id=agent_id,
        tenant_id=payload.tenant_id or "tenant-alpha",
        scopes=["customer:read", "weather:read", "http:egress"],
        allowed_tools=["db_query", "weather", "safe_http"],
        issuer="zero-trust-gateway-demo-agent"
    )

    if "weather" in prompt_lower or "temperature" in prompt_lower:
        action_dict = {
            "agent_id": agent_id,
            "tool": "weather",
            "operation": "GET",
            "destination": "https://api.weather.example/v1/current",
            "method": "GET",
            "args": {"city": "Bengaluru"}
        }
    else:
        # Default customer query intent
        action_dict = {
            "agent_id": agent_id,
            "tool": "db_query",
            "operation": "SELECT",
            "table": "customers",
            "destination": "sqlite://demo",
            "method": "INTERNAL",
            "args": {"columns": ["id", "name", "email"], "limit": 10}
        }

    # Step 3: Mediate action through runtime gateway
    result = await mediate_tool_action(action_dict, workload, db, correlation_id)

    return {
        "agent_id": agent_id,
        "answer": result["result"],
        "security": {
            "decision": result["decision"],
            "event_id": result["event_id"],
            "correlation_id": result["correlation_id"],
            "dlp_applied": result["dlp"]["redacted"]
        }
    }
