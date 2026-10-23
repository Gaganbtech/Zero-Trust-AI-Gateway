import json
import asyncio
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.database.models import AuditEvent, Incident, AgentRegistryItem
from app.audit.service import (
    get_dashboard_statistics,
    register_sse_subscriber,
    unregister_sse_subscriber,
    query_audit_events
)
from app.core.config import settings

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard & Telemetry"])


@router.get("/summary", summary="Dashboard Statistics Summary")
async def get_summary(db: Session = Depends(get_db)):
    """Aggregates security telemetry and metrics for the operator dashboard."""
    stats = get_dashboard_statistics(db)
    active_incidents = db.query(Incident).filter(Incident.status.in_(["OPEN", "INVESTIGATING"])).count()
    critical_incidents = db.query(Incident).filter(
        Incident.status.in_(["OPEN", "INVESTIGATING"]),
        Incident.severity == "CRITICAL"
    ).count()
    agent_count = db.query(AgentRegistryItem).count()

    # Calculate DLP findings count
    all_events = db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(100).all()
    dlp_total = sum(len(e.dlp_findings) for e in all_events)

    return {
        "total_events": stats["total"],
        "allowed_actions": stats["allowed"],
        "blocked_actions": stats["blocked"],
        "prompt_flags": stats["prompt_flagged"],
        "active_incidents": active_incidents,
        "critical_incidents": critical_incidents,
        "registered_agents": agent_count,
        "dlp_findings_detected": dlp_total,
        "policy_mode": "OPA" if settings.OPA_FAIL_CLOSED else "OPA with Local Fallback",
        "gateway_version": settings.VERSION,
        "environment": settings.ENVIRONMENT
    }


@router.get("/events/stream", summary="Live Security Events Stream (SSE)")
async def stream_live_events(request: Request):
    """
    Server-Sent Events (SSE) streaming endpoint.
    Emits live security events in real-time as they are evaluated and audited.
    """
    queue = register_sse_subscriber()

    async def event_generator():
        try:
            # Send initial keep-alive comment
            yield "event: ping\ndata: {}\n\n"
            while True:
                # If client disconnected, exit cleanly
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    payload = json.dumps(event)
                    yield f"event: security_event\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat every 15s
                    yield "event: ping\ndata: {}\n\n"
        finally:
            unregister_sse_subscriber(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )
