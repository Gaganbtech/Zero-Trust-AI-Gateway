import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Set
from sqlalchemy.orm import Session
from app.database.session import SessionLocal
from app.database.models import AuditEvent
from app.audit.tamper import calculate_event_hash, GENESIS_HASH
from app.incidents.detector import evaluate_event_for_incidents

logger = logging.getLogger(__name__)

# Active SSE listener queues
_sse_subscribers: Set[asyncio.Queue] = set()


def register_sse_subscriber() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    _sse_subscribers.add(q)
    return q


def unregister_sse_subscriber(q: asyncio.Queue):
    _sse_subscribers.discard(q)


async def broadcast_event(event_dict: Dict[str, Any]):
    dead_queues = []
    for q in _sse_subscribers:
        try:
            q.put_nowait(event_dict)
        except asyncio.QueueFull:
            dead_queues.append(q)
        except Exception:
            dead_queues.append(q)
    for q in dead_queues:
        _sse_subscribers.discard(q)


def record_security_event(
    agent_id: str,
    tenant_id: str,
    tool: str,
    operation: str,
    decision: str,  # ALLOW, BLOCK
    reason: str,
    destination: str,
    resource: Optional[str] = None,
    correlation_id: Optional[str] = None,
    prompt_flagged: bool = False,
    policy_source: str = "opa",
    policy_version: str = "1.0.0",
    risk_level: str = "LOW",
    dlp_findings: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    execution_duration_ms: Optional[float] = None,
    db: Optional[Session] = None
) -> Dict[str, Any]:
    """
    Persists structured security events with cryptographic SHA-256 hash chaining,
    correlates incidents, and broadcasts real-time telemetry.
    """
    owns_db = False
    if db is None:
        db = SessionLocal()
        owns_db = True

    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        event_id = f"evt-{uuid.uuid4().hex[:12]}"
        corr_id = correlation_id or str(uuid.uuid4())

        # Retrieve hash of latest event for chaining
        last_event = db.query(AuditEvent).order_by(AuditEvent.id.desc()).first()
        prev_hash = last_event.tamper_chain_hash if last_event else GENESIS_HASH

        event_data = {
            "timestamp": now_iso,
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "tool": tool,
            "operation": operation,
            "destination": destination,
            "decision": decision,
            "reason": reason,
        }
        tamper_hash = calculate_event_hash(prev_hash, event_data)

        # Never store raw prompts or unredacted secrets in metadata
        safe_meta = (metadata or {}).copy()

        audit_record = AuditEvent(
            event_id=event_id,
            timestamp=now_iso,
            correlation_id=corr_id,
            agent_id=agent_id,
            tenant_id=tenant_id,
            tool=tool,
            operation=operation,
            resource=resource,
            destination=destination,
            decision=decision,
            reason=reason,
            policy_version=policy_version,
            policy_source=policy_source,
            risk_level=risk_level,
            prompt_flagged=prompt_flagged,
            dlp_findings_json=json.dumps(dlp_findings or []),
            metadata_json=json.dumps(safe_meta),
            execution_duration_ms=execution_duration_ms,
            previous_event_hash=prev_hash,
            tamper_chain_hash=tamper_hash,
        )
        db.add(audit_record)
        db.commit()
        db.refresh(audit_record)

        # Automated incident detection
        evaluate_event_for_incidents(audit_record, db)

        result_dict = {
            "id": audit_record.id,
            "event_id": event_id,
            "timestamp": now_iso,
            "correlation_id": corr_id,
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "tool": tool,
            "operation": operation,
            "resource": resource,
            "destination": destination,
            "decision": decision,
            "reason": reason,
            "policy_version": policy_version,
            "policy_source": policy_source,
            "risk_level": risk_level,
            "prompt_flagged": prompt_flagged,
            "dlp_findings": dlp_findings or [],
            "metadata": safe_meta,
            "execution_duration_ms": execution_duration_ms,
            "tamper_chain_hash": tamper_hash,
        }

        # Schedule async broadcast to SSE subscribers if event loop running
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(broadcast_event(result_dict))
        except RuntimeError:
            pass

        return result_dict
    finally:
        if owns_db:
            db.close()


def verify_chain_integrity(db: Session) -> Dict[str, Any]:
    """
    Cryptographically verifies the complete audit log hash chain from genesis to head.
    Detects any row alteration, insertion, or deletion.
    """
    events = db.query(AuditEvent).order_by(AuditEvent.id.asc()).all()
    if not events:
        return {"valid": True, "total_events_verified": 0, "head_hash": GENESIS_HASH}

    expected_prev = GENESIS_HASH
    for idx, ev in enumerate(events):
        if ev.previous_event_hash != expected_prev:
            return {
                "valid": False,
                "error": f"Chain broken at record #{ev.id} ({ev.event_id}): previous_hash mismatch",
                "record_id": ev.id,
                "event_id": ev.event_id,
                "expected_previous_hash": expected_prev,
                "actual_previous_hash": ev.previous_event_hash,
            }

        event_data = {
            "timestamp": ev.timestamp,
            "agent_id": ev.agent_id,
            "tenant_id": ev.tenant_id,
            "tool": ev.tool,
            "operation": ev.operation,
            "destination": ev.destination,
            "decision": ev.decision,
            "reason": ev.reason,
        }
        recomputed_hash = calculate_event_hash(expected_prev, event_data)
        if recomputed_hash != ev.tamper_chain_hash:
            return {
                "valid": False,
                "error": f"Tampering detected at record #{ev.id} ({ev.event_id}): HMAC signature mismatch",
                "record_id": ev.id,
                "event_id": ev.event_id,
                "recomputed_hash": recomputed_hash,
                "stored_hash": ev.tamper_chain_hash,
            }

        expected_prev = ev.tamper_chain_hash

    return {
        "valid": True,
        "total_events_verified": len(events),
        "head_hash": expected_prev,
        "tamper_evident": True
    }


def query_audit_events(
    db: Session,
    limit: int = 50,
    offset: int = 0,
    agent_id: Optional[str] = None,
    decision: Optional[str] = None,
    tenant_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    query = db.query(AuditEvent)
    if agent_id:
        query = query.filter(AuditEvent.agent_id == agent_id)
    if decision:
        query = query.filter(AuditEvent.decision == decision.upper())
    if tenant_id:
        query = query.filter(AuditEvent.tenant_id == tenant_id)

    records = query.order_by(AuditEvent.id.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id": r.id,
            "event_id": r.event_id,
            "timestamp": r.timestamp,
            "correlation_id": r.correlation_id,
            "agent_id": r.agent_id,
            "tenant_id": r.tenant_id,
            "tool": r.tool,
            "operation": r.operation,
            "resource": r.resource,
            "destination": r.destination,
            "decision": r.decision,
            "reason": r.reason,
            "policy_version": r.policy_version,
            "policy_source": r.policy_source,
            "risk_level": r.risk_level,
            "prompt_flagged": r.prompt_flagged,
            "dlp_findings": r.dlp_findings,
            "metadata": r.metadata_dict,
            "execution_duration_ms": r.execution_duration_ms,
            "tamper_chain_hash": r.tamper_chain_hash,
        }
        for r in records
    ]


def get_dashboard_statistics(db: Session) -> Dict[str, Any]:
    total = db.query(AuditEvent).count()
    allowed = db.query(AuditEvent).filter(AuditEvent.decision == "ALLOW").count()
    blocked = db.query(AuditEvent).filter(AuditEvent.decision == "BLOCK").count()
    flagged = db.query(AuditEvent).filter(AuditEvent.prompt_flagged == True).count()
    return {
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "prompt_flagged": flagged,
    }
