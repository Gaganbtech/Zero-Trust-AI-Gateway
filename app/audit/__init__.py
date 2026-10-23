from .service import (
    record_security_event,
    verify_chain_integrity,
    query_audit_events,
    get_dashboard_statistics,
    register_sse_subscriber,
    unregister_sse_subscriber,
)
from app.database.init_db import init_database
from app.database.session import SessionLocal
from app.core.config import settings

# Backward compatibility wrappers for legacy tests
def init_db():
    init_database()

def log_event(agent_id, tool, decision, reason, destination, operation, prompt_flagged=False, metadata=None):
    res = record_security_event(
        agent_id=agent_id,
        tenant_id="tenant-alpha",
        tool=tool,
        operation=operation,
        decision=decision,
        reason=reason,
        destination=destination,
        prompt_flagged=prompt_flagged,
        metadata=metadata
    )
    return res

def recent_events(limit=50):
    db = SessionLocal()
    try:
        return query_audit_events(db, limit=limit)
    finally:
        db.close()

def stats():
    db = SessionLocal()
    try:
        return get_dashboard_statistics(db)
    finally:
        db.close()

__all__ = [
    "record_security_event",
    "verify_chain_integrity",
    "query_audit_events",
    "get_dashboard_statistics",
    "register_sse_subscriber",
    "unregister_sse_subscriber",
    "init_db",
    "log_event",
    "recent_events",
    "stats",
    "settings",
]
