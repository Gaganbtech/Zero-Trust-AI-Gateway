import time
import logging
from typing import Dict, Any, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.auth.workload import VerifiedWorkload
from app.tools.registry import registry
from app.policies.client import evaluate_policy
from app.dlp.engine import inspect_and_sanitize_payload, DLPAction
from app.audit.service import record_security_event
from app.network.ssrf import validate_destination_safety
from app.core.config import settings

logger = logging.getLogger(__name__)


async def mediate_tool_action(
    action_data: Dict[str, Any],
    workload: VerifiedWorkload,
    db: Session,
    correlation_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Core Zero-Trust Mediation Pipeline (12-step execution sequence):
    
    1. Authenticate the workload (Provided by workload dependency)
    2. Validate request schema
    3. Verify tenant and resource ownership
    4. Validate requested operation against tool definition
    5. Validate destination and network restrictions
    6. Evaluate runtime policy via OPA
    7. Apply argument and risk checks
    8. Execute approved operation using restricted credentials
    9. Validate returned result
    10. Apply data classification and DLP sanitization
    11. Record final decision in tamper-evident audit log
    12. Return authorized, sanitized result
    """
    start_time = time.perf_counter()

    tool_name = action_data.get("tool")
    operation = (action_data.get("operation") or "").upper()
    destination = action_data.get("destination", "")
    method = (action_data.get("method") or "").upper()
    resource = action_data.get("table") or action_data.get("resource")
    args = action_data.get("args") or {}

    # Step 1: Workload Identity verification & impersonation check
    requested_agent_id = action_data.get("agent_id")
    if requested_agent_id and requested_agent_id != workload.agent_id:
        record_security_event(
            agent_id=workload.agent_id,
            tenant_id=workload.tenant_id,
            tool=tool_name or "unknown",
            operation=operation,
            decision="BLOCK",
            reason="agent_impersonation_attempt",
            destination=destination,
            resource=resource,
            correlation_id=correlation_id,
            risk_level="CRITICAL",
            metadata={"claimed_agent_id": requested_agent_id, "verified_agent_id": workload.agent_id},
            db=db
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Agent identity impersonation detected and blocked.",
                "verified_identity": workload.agent_id,
                "reason": "agent_impersonation_attempt"
            }
        )

    # Step 2 & 3: Tool definition and tenant ownership
    tool_def = registry.get_definition(tool_name)
    if not tool_def:
        record_security_event(
            agent_id=workload.agent_id,
            tenant_id=workload.tenant_id,
            tool=tool_name or "unknown",
            operation=operation,
            decision="BLOCK",
            reason="unknown_or_unregistered_tool",
            destination=destination,
            resource=resource,
            correlation_id=correlation_id,
            risk_level="HIGH",
            db=db
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": f"Tool '{tool_name}' is not registered in security gateway.", "reason": "unknown_tool"}
        )

    # Step 4: Validate requested operation
    if operation not in tool_def.allowed_operations:
        record_security_event(
            agent_id=workload.agent_id,
            tenant_id=workload.tenant_id,
            tool=tool_name,
            operation=operation,
            decision="BLOCK",
            reason="disallowed_tool_operation",
            destination=destination,
            resource=resource,
            correlation_id=correlation_id,
            risk_level="HIGH",
            db=db
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": f"Operation '{operation}' is not permitted for tool '{tool_name}'.", "reason": "disallowed_tool_operation"}
        )

    # Step 5: Network / Destination validation
    if destination.startswith("http://") or destination.startswith("https://"):
        try:
            validate_destination_safety(destination, settings.ALLOWED_OUTBOUND_DOMAINS)
        except ValueError as ssrf_err:
            reason_code = str(ssrf_err)
            record_security_event(
                agent_id=workload.agent_id,
                tenant_id=workload.tenant_id,
                tool=tool_name,
                operation=operation,
                decision="BLOCK",
                reason=reason_code,
                destination=destination,
                resource=resource,
                correlation_id=correlation_id,
                risk_level="HIGH",
                metadata={"ssrf_rejection": True},
                db=db
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "Destination blocked by network egress security policy.", "reason": reason_code}
            )

    # Step 6: Evaluate OPA Policy
    policy_input = {
        "agent_id": workload.agent_id,
        "tenant_id": workload.tenant_id,
        "scopes": workload.scopes,
        "allowed_tools": workload.allowed_tools,
        "tool": tool_name,
        "operation": operation,
        "table": resource,
        "destination": destination,
        "method": method,
        "risk_level": tool_def.risk_classification,
        "args": args,
    }

    allowed, reason, source = await evaluate_policy(policy_input)
    if not allowed:
        record_security_event(
            agent_id=workload.agent_id,
            tenant_id=workload.tenant_id,
            tool=tool_name,
            operation=operation,
            decision="BLOCK",
            reason=reason,
            destination=destination,
            resource=resource,
            correlation_id=correlation_id,
            policy_source=source,
            risk_level=tool_def.risk_classification,
            metadata={"policy_input": policy_input},
            db=db
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Action blocked by runtime security policy.", "reason": reason, "policy_source": source}
        )

    # Step 7 & 8: Execute tool with least-privilege credentials
    executor = registry.get_executor(tool_name)
    if not executor:
        raise HTTPException(status_code=500, detail="Tool executor not found")

    try:
        raw_result = await executor(args, workload)
    except Exception as exec_err:
        logger.error("Tool execution error: %s", exec_err)
        record_security_event(
            agent_id=workload.agent_id,
            tenant_id=workload.tenant_id,
            tool=tool_name,
            operation=operation,
            decision="BLOCK",
            reason="execution_guard_denied",
            destination=destination,
            resource=resource,
            correlation_id=correlation_id,
            policy_source=source,
            risk_level=tool_def.risk_classification,
            db=db
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Execution guard denied tool execution.", "reason": str(exec_err)}
        )

    # Step 9 & 10: Apply recursive DLP sanitization
    clean_result, dlp_findings = inspect_and_sanitize_payload(raw_result, DLPAction.REDACT)

    # Step 11: Persist final execution event in tamper-evident audit chain
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    event = record_security_event(
        agent_id=workload.agent_id,
        tenant_id=workload.tenant_id,
        tool=tool_name,
        operation=operation,
        decision="ALLOW",
        reason=reason,
        destination=destination,
        resource=resource,
        correlation_id=correlation_id,
        policy_source=source,
        risk_level=tool_def.risk_classification,
        dlp_findings=dlp_findings,
        execution_duration_ms=duration_ms,
        metadata={
            "result_type": type(raw_result).__name__,
            "rows_returned": len(raw_result) if isinstance(raw_result, list) else 1
        },
        db=db
    )

    # Step 12: Return only the sanitized result
    return {
        "decision": "ALLOW",
        "event_id": event["event_id"],
        "correlation_id": event["correlation_id"],
        "result": clean_result,
        "dlp": {
            "redacted": bool(dlp_findings),
            "findings": dlp_findings
        },
        "execution_duration_ms": duration_ms
    }
