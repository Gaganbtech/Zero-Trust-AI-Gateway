from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.database.models import AuditEvent
from app.audit.service import query_audit_events, verify_chain_integrity
from app.auth.dependencies import get_current_user
from app.database.models import User

router = APIRouter(prefix="/api/v1/audit", tags=["Audit & Tamper-Evidence"])


@router.get("/events", summary="Query Structured Audit Events")
async def get_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    agent_id: Optional[str] = Query(None),
    decision: Optional[str] = Query(None),
    tenant_id: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Retrieves paginated and filtered security audit events.
    Excludes sensitive raw prompts and unredacted values.
    """
    events = query_audit_events(
        db=db,
        limit=limit,
        offset=offset,
        agent_id=agent_id,
        decision=decision,
        tenant_id=tenant_id
    )
    total_count = db.query(AuditEvent).count()
    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "events": events
    }


@router.get("/events/{event_id}", summary="Get Event Details")
async def get_event_detail(
    event_id: str,
    db: Session = Depends(get_db)
):
    event = db.query(AuditEvent).filter(AuditEvent.event_id == event_id).first()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit event not found")
    return {
        "id": event.id,
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "correlation_id": event.correlation_id,
        "agent_id": event.agent_id,
        "tenant_id": event.tenant_id,
        "tool": event.tool,
        "operation": event.operation,
        "resource": event.resource,
        "destination": event.destination,
        "decision": event.decision,
        "reason": event.reason,
        "policy_version": event.policy_version,
        "policy_source": event.policy_source,
        "risk_level": event.risk_level,
        "prompt_flagged": event.prompt_flagged,
        "dlp_findings": event.dlp_findings,
        "metadata": event.metadata_dict,
        "execution_duration_ms": event.execution_duration_ms,
        "previous_event_hash": event.previous_event_hash,
        "tamper_chain_hash": event.tamper_chain_hash,
    }


@router.get("/verify", summary="Verify Tamper-Evident Hash Chain Integrity")
async def verify_audit_integrity(
    db: Session = Depends(get_db)
):
    """
    Cryptographically verifies the SHA-256 HMAC hash chain across all audit records.
    Returns status: verified or flags exact index of tampering.
    """
    return verify_chain_integrity(db)
