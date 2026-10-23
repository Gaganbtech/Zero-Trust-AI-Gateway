import uuid
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.database.models import Incident, AuditEvent


def evaluate_event_for_incidents(
    event: AuditEvent,
    db: Session
) -> Optional[Incident]:
    """
    Evaluates newly recorded audit events against security incident correlation rules.
    Creates structured incident records with actionable remediation recommendations.
    """
    incident: Optional[Incident] = None

    # Rule 1: Destructive Database Operation Attempt
    if event.operation.upper() in {"DROP", "DELETE", "UPDATE", "ALTER", "TRUNCATE"} or event.reason == "destructive_sql_prohibited":
        incident = Incident(
            id=f"inc-{uuid.uuid4().hex[:12]}",
            title=f"Destructive operation attempted by agent '{event.agent_id}'",
            severity="CRITICAL",
            status="OPEN",
            agent_id=event.agent_id,
            tenant_id=event.tenant_id,
            rule_name="DESTRUCTIVE_OPERATION_ATTEMPT",
            description=f"Agent attempted destructive operation '{event.operation}' on resource '{event.resource or event.tool}'. Gateway blocked execution.",
            evidence_event_ids_json=json.dumps([event.event_id]),
            remediation_guidance=(
                "1. Immediately review the AI agent prompt and workflow definition.\n"
                "2. Ensure model temperature and system instructions prevent arbitrary DDL/DML emission.\n"
                "3. Consider quarantining the agent credential if recurring."
            )
        )

    # Rule 2: Secret Disclosure / Data Exfiltration Attempt
    elif event.prompt_flagged and "secret" in event.reason.lower() or event.reason == "SECRET_DISCLOSURE_ATTEMPT":
        incident = Incident(
            id=f"inc-{uuid.uuid4().hex[:12]}",
            title=f"Credential or data exfiltration suspected from '{event.agent_id}'",
            severity="HIGH",
            status="OPEN",
            agent_id=event.agent_id,
            tenant_id=event.tenant_id,
            rule_name="DATA_EXFILTRATION_SUSPECTED",
            description="Input scanner flagged prompt attempting to elicit credentials, API keys, or raw customer dumps.",
            evidence_event_ids_json=json.dumps([event.event_id]),
            remediation_guidance=(
                "1. Inspect incoming agent session history for prompt injection or jailbreak attempts.\n"
                "2. Verify whether untrusted external content (e.g., retrieved emails, web pages) was ingested.\n"
                "3. Validate data classification and DLP masking rules."
            )
        )

    # Rule 3: SSRF / Unapproved Network Egress
    elif "ssrf_" in event.reason.lower() or event.reason == "unapproved_destination":
        incident = Incident(
            id=f"inc-{uuid.uuid4().hex[:12]}",
            title=f"Network egress policy violation / SSRF attempt to {event.destination}",
            severity="HIGH",
            status="OPEN",
            agent_id=event.agent_id,
            tenant_id=event.tenant_id,
            rule_name="SSRF_EGRESS_VIOLATION",
            description=f"Agent attempted outbound HTTP request to unapproved or dangerous destination '{event.destination}'. Reason: {event.reason}.",
            evidence_event_ids_json=json.dumps([event.event_id]),
            remediation_guidance=(
                "1. Verify if the target destination is a legitimate business API requiring addition to the domain allowlist.\n"
                "2. Check if prompt injection misled the agent into accessing an internal IP or cloud metadata service.\n"
                "3. Confirm network security group egress rules restrict direct egress from agent containers."
            )
        )

    # Rule 4: Repeated Authorization Denials (Brute-force / Probe)
    elif event.decision == "BLOCK":
        # Check count of blocks for this agent in past 10 minutes
        ten_minutes_ago = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        recent_blocks = db.query(AuditEvent).filter(
            AuditEvent.agent_id == event.agent_id,
            AuditEvent.decision == "BLOCK",
            AuditEvent.timestamp >= ten_minutes_ago
        ).count()

        if recent_blocks >= 3:
            # Check if an open incident already exists for this rule and agent
            existing = db.query(Incident).filter(
                Incident.agent_id == event.agent_id,
                Incident.rule_name == "REPEATED_AUTHORIZATION_DENIALS",
                Incident.status == "OPEN"
            ).first()

            if not existing:
                incident = Incident(
                    id=f"inc-{uuid.uuid4().hex[:12]}",
                    title=f"Repeated authorization denials ({recent_blocks}+) for agent '{event.agent_id}'",
                    severity="HIGH",
                    status="OPEN",
                    agent_id=event.agent_id,
                    tenant_id=event.tenant_id,
                    rule_name="REPEATED_AUTHORIZATION_DENIALS",
                    description=f"Agent '{event.agent_id}' has triggered {recent_blocks} authorization denials within a 10-minute window.",
                    evidence_event_ids_json=json.dumps([event.event_id]),
                    remediation_guidance=(
                        "1. Investigate whether the agent workload has drifted from its intended tool schema.\n"
                        "2. Inspect agent tokens for potential credential compromise or misuse.\n"
                        "3. Update OPA policy if new tool capabilities were legitimately assigned to this agent."
                    )
                )

    if incident:
        db.add(incident)
        db.commit()
        db.refresh(incident)

    return incident
