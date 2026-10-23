import pytest
from app.database.session import SessionLocal
from app.database.models import AuditEvent
from app.audit.service import record_security_event, verify_chain_integrity


def test_audit_hash_chain_creation_and_integrity(client):
    db = SessionLocal()
    try:
        # Create 3 events
        ev1 = record_security_event(
            agent_id="demo-agent",
            tenant_id="tenant-alpha",
            tool="db_query",
            operation="SELECT",
            decision="ALLOW",
            reason="policy_allow",
            destination="sqlite://demo",
            db=db
        )
        ev2 = record_security_event(
            agent_id="demo-agent",
            tenant_id="tenant-alpha",
            tool="weather",
            operation="GET",
            decision="ALLOW",
            reason="policy_allow",
            destination="https://api.weather.example/v1/current",
            db=db
        )
        ev3 = record_security_event(
            agent_id="demo-agent",
            tenant_id="tenant-alpha",
            tool="db_query",
            operation="DROP",
            decision="BLOCK",
            reason="destructive_sql_prohibited",
            destination="sqlite://demo",
            db=db
        )

        # 1. Verify that integrity check passes on unmodified logs
        report = verify_chain_integrity(db)
        assert report["valid"] is True
        assert report["total_events_verified"] >= 3

        # 2. Simulate adversary tampering with an audit record (modifying decision from BLOCK to ALLOW)
        record = db.query(AuditEvent).filter(AuditEvent.event_id == ev3["event_id"]).first()
        record.decision = "ALLOW"
        db.commit()

        # 3. Verify that tampering is immediately detected and pinpointed
        tampered_report = verify_chain_integrity(db)
        assert tampered_report["valid"] is False
        assert "Tampering detected" in tampered_report["error"]
        assert tampered_report["event_id"] == ev3["event_id"]
    finally:
        db.close()
