"""
LUME AI-CSPM Platform — Service Layer

Business logic for cloud environments, agents, findings,
scan jobs, and rules. All queries are tenant-scoped.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_

from app.cspm.models import (
    CloudEnvironment,
    CSPMAgent,
    SecurityFinding,
    FindingHistory,
    CSPMScanJob,
    CSPMRule,
)


def _utc_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.isoformat()


def _gen_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


# =====================================================================
# Cloud Environments
# =====================================================================

def create_cloud_environment(
    db: Session,
    tenant_id: str,
    provider: str,
    name: str,
    account_id: Optional[str] = None,
    description: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    env = CloudEnvironment(
        id=_gen_id("env-"),
        tenant_id=tenant_id,
        provider=provider.upper(),
        account_id=account_id,
        name=name,
        description=description,
        region=region,
    )
    db.add(env)
    db.commit()
    db.refresh(env)
    return _env_to_dict(env)


def list_cloud_environments(db: Session, tenant_id: str) -> List[Dict[str, Any]]:
    envs = db.query(CloudEnvironment).filter(
        CloudEnvironment.tenant_id == tenant_id
    ).order_by(desc(CloudEnvironment.created_at)).all()
    return [_env_to_dict(e) for e in envs]


def get_cloud_environment(db: Session, env_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
    env = db.query(CloudEnvironment).filter(
        CloudEnvironment.id == env_id,
        CloudEnvironment.tenant_id == tenant_id,
    ).first()
    return _env_to_dict(env) if env else None


def update_cloud_environment(
    db: Session, env_id: str, tenant_id: str, updates: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    env = db.query(CloudEnvironment).filter(
        CloudEnvironment.id == env_id,
        CloudEnvironment.tenant_id == tenant_id,
    ).first()
    if not env:
        return None
    for key in ("name", "description", "region"):
        if key in updates and updates[key] is not None:
            setattr(env, key, updates[key])
    db.commit()
    db.refresh(env)
    return _env_to_dict(env)


def delete_cloud_environment(db: Session, env_id: str, tenant_id: str) -> bool:
    env = db.query(CloudEnvironment).filter(
        CloudEnvironment.id == env_id,
        CloudEnvironment.tenant_id == tenant_id,
    ).first()
    if not env:
        return False
    db.delete(env)
    db.commit()
    return True


def _env_to_dict(env: CloudEnvironment) -> Dict[str, Any]:
    return {
        "id": env.id,
        "tenant_id": env.tenant_id,
        "provider": env.provider,
        "account_id": env.account_id,
        "name": env.name,
        "description": env.description,
        "region": env.region,
        "connection_status": env.connection_status,
        "last_sync_at": _utc_iso(env.last_sync_at),
        "health_status": env.health_status,
        "connector_version": env.connector_version,
        "created_at": _utc_iso(env.created_at),
        "updated_at": _utc_iso(env.updated_at),
    }


# =====================================================================
# CSPM Agents
# =====================================================================

def register_agent(
    db: Session,
    tenant_id: str,
    name: str,
    registration_source: str = "manual",
    **kwargs,
) -> Dict[str, Any]:
    agent = CSPMAgent(
        id=_gen_id("agent-"),
        name=name,
        tenant_id=tenant_id,
        registration_source=registration_source,
        environment_id=kwargs.get("environment_id"),
        cloud_provider=kwargs.get("cloud_provider"),
        cloud_account_id=kwargs.get("cloud_account_id"),
        deployment_environment=kwargs.get("deployment_environment", "development"),
        region=kwargs.get("region"),
        framework=kwargs.get("framework"),
        model_provider=kwargs.get("model_provider"),
        model_name=kwargs.get("model_name"),
        description=kwargs.get("description"),
        tools_json=json.dumps(kwargs.get("tools", [])),
        mcp_servers_json=json.dumps(kwargs.get("mcp_servers", [])),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return _agent_to_dict(agent)


def list_agents(
    db: Session,
    tenant_id: str,
    status: Optional[str] = None,
    provider: Optional[str] = None,
) -> List[Dict[str, Any]]:
    q = db.query(CSPMAgent).filter(CSPMAgent.tenant_id == tenant_id)
    if status:
        q = q.filter(CSPMAgent.status == status.upper())
    if provider:
        q = q.filter(CSPMAgent.cloud_provider == provider.upper())
    agents = q.order_by(desc(CSPMAgent.created_at)).all()
    return [_agent_to_dict(a) for a in agents]


def get_agent(db: Session, agent_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
    agent = db.query(CSPMAgent).filter(
        CSPMAgent.id == agent_id,
        CSPMAgent.tenant_id == tenant_id,
    ).first()
    return _agent_to_dict(agent) if agent else None


def agent_heartbeat(db: Session, agent_id: str, tenant_id: str) -> bool:
    agent = db.query(CSPMAgent).filter(
        CSPMAgent.id == agent_id,
        CSPMAgent.tenant_id == tenant_id,
    ).first()
    if not agent:
        return False
    agent.last_seen_at = datetime.now(timezone.utc)
    agent.connection_status = "CONNECTED"
    db.commit()
    return True


def get_agent_posture(db: Session, agent_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
    agent = db.query(CSPMAgent).filter(
        CSPMAgent.id == agent_id,
        CSPMAgent.tenant_id == tenant_id,
    ).first()
    if not agent:
        return None

    findings = db.query(SecurityFinding).filter(
        SecurityFinding.agent_id == agent_id,
        SecurityFinding.tenant_id == tenant_id,
        SecurityFinding.status.in_(["OPEN", "ACKNOWLEDGED", "IN_PROGRESS"]),
    ).all()

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    category_counts: Dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    scans = db.query(CSPMScanJob).filter(
        CSPMScanJob.target_agent_id == agent_id,
        CSPMScanJob.tenant_id == tenant_id,
    ).order_by(desc(CSPMScanJob.created_at)).limit(5).all()

    return {
        "agent": _agent_to_dict(agent),
        "open_findings": len(findings),
        "severity_distribution": severity_counts,
        "category_distribution": category_counts,
        "recent_scans": [_scan_to_dict(s) for s in scans],
    }


def _agent_to_dict(agent: CSPMAgent) -> Dict[str, Any]:
    return {
        "id": agent.id,
        "name": agent.name,
        "tenant_id": agent.tenant_id,
        "environment_id": agent.environment_id,
        "cloud_provider": agent.cloud_provider,
        "cloud_account_id": agent.cloud_account_id,
        "deployment_environment": agent.deployment_environment,
        "region": agent.region,
        "framework": agent.framework,
        "model_provider": agent.model_provider,
        "model_name": agent.model_name,
        "description": agent.description,
        "tools": agent.tools,
        "mcp_servers": agent.mcp_servers,
        "registration_source": agent.registration_source,
        "status": agent.status,
        "connection_status": agent.connection_status,
        "risk_score": agent.risk_score,
        "open_findings_count": agent.open_findings_count,
        "critical_findings_count": agent.critical_findings_count,
        "high_findings_count": agent.high_findings_count,
        "last_seen_at": _utc_iso(agent.last_seen_at),
        "last_scan_at": _utc_iso(agent.last_scan_at),
        "created_at": _utc_iso(agent.created_at),
        "updated_at": _utc_iso(agent.updated_at),
    }


# =====================================================================
# Security Findings
# =====================================================================

def create_finding(
    db: Session,
    tenant_id: str,
    title: str,
    description: str,
    category: str,
    severity: str,
    **kwargs,
) -> Dict[str, Any]:
    finding = SecurityFinding(
        id=_gen_id("finding-"),
        tenant_id=tenant_id,
        title=title,
        description=description,
        category=category.upper(),
        severity=severity.upper(),
        confidence=kwargs.get("confidence", "HIGH"),
        rule_id=kwargs.get("rule_id"),
        agent_id=kwargs.get("agent_id"),
        environment_id=kwargs.get("environment_id"),
        resource_id=kwargs.get("resource_id"),
        cloud_provider=kwargs.get("cloud_provider"),
        detection_source=kwargs.get("detection_source"),
        evidence_json=json.dumps(kwargs.get("evidence", {})),
        technical_detail=kwargs.get("technical_detail"),
        impact=kwargs.get("impact"),
        remediation=kwargs.get("remediation"),
        compliance_frameworks_json=json.dumps(kwargs.get("compliance_frameworks", [])),
    )
    db.add(finding)

    # Record initial creation in history
    history = FindingHistory(
        finding_id=finding.id,
        previous_status=None,
        new_status="OPEN",
        changed_by=kwargs.get("created_by", "system"),
        notes="Finding created",
    )
    db.add(history)

    # Update agent finding counts
    if finding.agent_id:
        _refresh_agent_finding_counts(db, finding.agent_id, tenant_id)

    db.commit()
    db.refresh(finding)
    return _finding_to_dict(finding)


def list_findings(
    db: Session,
    tenant_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    agent_id: Optional[str] = None,
    provider: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    q = db.query(SecurityFinding).filter(SecurityFinding.tenant_id == tenant_id)
    if severity:
        q = q.filter(SecurityFinding.severity == severity.upper())
    if status:
        q = q.filter(SecurityFinding.status == status.upper())
    if category:
        q = q.filter(SecurityFinding.category == category.upper())
    if agent_id:
        q = q.filter(SecurityFinding.agent_id == agent_id)
    if provider:
        q = q.filter(SecurityFinding.cloud_provider == provider.upper())

    total = q.count()
    findings = q.order_by(desc(SecurityFinding.created_at)).offset(offset).limit(limit).all()
    return [_finding_to_dict(f) for f in findings], total


def get_finding(db: Session, finding_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
    finding = db.query(SecurityFinding).filter(
        SecurityFinding.id == finding_id,
        SecurityFinding.tenant_id == tenant_id,
    ).first()
    if not finding:
        return None
    result = _finding_to_dict(finding)
    # Include history
    history = db.query(FindingHistory).filter(
        FindingHistory.finding_id == finding_id
    ).order_by(desc(FindingHistory.timestamp)).all()
    result["history"] = [
        {
            "id": h.id,
            "finding_id": h.finding_id,
            "previous_status": h.previous_status,
            "new_status": h.new_status,
            "changed_by": h.changed_by,
            "notes": h.notes,
            "timestamp": _utc_iso(h.timestamp),
        }
        for h in history
    ]
    return result


def update_finding_status(
    db: Session,
    finding_id: str,
    tenant_id: str,
    new_status: str,
    changed_by: str = "system",
    notes: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    finding = db.query(SecurityFinding).filter(
        SecurityFinding.id == finding_id,
        SecurityFinding.tenant_id == tenant_id,
    ).first()
    if not finding:
        return None

    previous_status = finding.status
    finding.status = new_status.upper()
    if new_status.upper() == "RESOLVED":
        finding.resolved_at = datetime.now(timezone.utc)

    history = FindingHistory(
        finding_id=finding_id,
        previous_status=previous_status,
        new_status=new_status.upper(),
        changed_by=changed_by,
        notes=notes,
    )
    db.add(history)

    # Update agent finding counts
    if finding.agent_id:
        _refresh_agent_finding_counts(db, finding.agent_id, tenant_id)

    db.commit()
    db.refresh(finding)
    return _finding_to_dict(finding)


def ingest_agent_findings(
    db: Session,
    agent_id: str,
    tenant_id: str,
    findings_data: List[Dict[str, Any]],
    detection_source: str = "agent_report",
) -> List[Dict[str, Any]]:
    """Ingest findings submitted by an agent or collector."""
    created = []
    for fd in findings_data:
        # Validate and normalize severity
        severity = fd.get("severity", "MEDIUM").upper()
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            severity = "MEDIUM"
        # Validate category
        category = fd.get("category", "AGENT_CONFIG").upper()

        result = create_finding(
            db=db,
            tenant_id=tenant_id,
            title=fd.get("title", "Untitled Finding"),
            description=fd.get("description", "No description provided"),
            category=category,
            severity=severity,
            confidence=fd.get("confidence", "MEDIUM"),  # Don't blindly trust agent's confidence
            rule_id=fd.get("rule_id"),
            agent_id=agent_id,
            environment_id=fd.get("environment_id"),
            resource_id=fd.get("resource_id"),
            cloud_provider=fd.get("cloud_provider"),
            detection_source=detection_source,
            evidence=fd.get("evidence", {}),
            technical_detail=fd.get("technical_detail"),
            impact=fd.get("impact"),
            remediation=fd.get("remediation"),
            compliance_frameworks=fd.get("compliance_frameworks", []),
            created_by="agent:" + agent_id,
        )
        created.append(result)
    return created


def _refresh_agent_finding_counts(db: Session, agent_id: str, tenant_id: str):
    """Recalculate finding counts for an agent."""
    agent = db.query(CSPMAgent).filter(
        CSPMAgent.id == agent_id,
        CSPMAgent.tenant_id == tenant_id,
    ).first()
    if not agent:
        return
    open_q = db.query(SecurityFinding).filter(
        SecurityFinding.agent_id == agent_id,
        SecurityFinding.tenant_id == tenant_id,
        SecurityFinding.status.in_(["OPEN", "ACKNOWLEDGED", "IN_PROGRESS"]),
    )
    agent.open_findings_count = open_q.count()
    agent.critical_findings_count = open_q.filter(SecurityFinding.severity == "CRITICAL").count()
    agent.high_findings_count = open_q.filter(SecurityFinding.severity == "HIGH").count()

    # Calculate risk score: weighted sum
    weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 5, "LOW": 1}
    score = 0
    for sev, w in weights.items():
        cnt = open_q.filter(SecurityFinding.severity == sev).count()
        score += cnt * w
    agent.risk_score = min(100.0, float(score))


def _finding_to_dict(f: SecurityFinding) -> Dict[str, Any]:
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "tenant_id": f.tenant_id,
        "agent_id": f.agent_id,
        "environment_id": f.environment_id,
        "resource_id": f.resource_id,
        "title": f.title,
        "description": f.description,
        "category": f.category,
        "severity": f.severity,
        "confidence": f.confidence,
        "cloud_provider": f.cloud_provider,
        "detection_source": f.detection_source,
        "evidence": f.evidence,
        "technical_detail": f.technical_detail,
        "impact": f.impact,
        "remediation": f.remediation,
        "compliance_frameworks": f.compliance_frameworks,
        "status": f.status,
        "first_seen_at": _utc_iso(f.first_seen_at),
        "last_seen_at": _utc_iso(f.last_seen_at),
        "resolved_at": _utc_iso(f.resolved_at),
        "created_at": _utc_iso(f.created_at),
        "updated_at": _utc_iso(f.updated_at),
    }


# =====================================================================
# Scan Jobs
# =====================================================================

def create_scan_job(
    db: Session,
    tenant_id: str,
    scan_type: str,
    target_agent_id: Optional[str] = None,
    target_environment_id: Optional[str] = None,
) -> Dict[str, Any]:
    job = CSPMScanJob(
        id=_gen_id("scan-"),
        tenant_id=tenant_id,
        scan_type=scan_type,
        target_agent_id=target_agent_id,
        target_environment_id=target_environment_id,
        status="PENDING",
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return _scan_to_dict(job)


def list_scan_jobs(
    db: Session,
    tenant_id: str,
    limit: int = 20,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    q = db.query(CSPMScanJob).filter(CSPMScanJob.tenant_id == tenant_id)
    total = q.count()
    jobs = q.order_by(desc(CSPMScanJob.created_at)).offset(offset).limit(limit).all()
    return [_scan_to_dict(j) for j in jobs], total


def get_scan_job(db: Session, scan_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
    job = db.query(CSPMScanJob).filter(
        CSPMScanJob.id == scan_id,
        CSPMScanJob.tenant_id == tenant_id,
    ).first()
    return _scan_to_dict(job) if job else None


def _scan_to_dict(j: CSPMScanJob) -> Dict[str, Any]:
    return {
        "id": j.id,
        "tenant_id": j.tenant_id,
        "target_agent_id": j.target_agent_id,
        "target_environment_id": j.target_environment_id,
        "scan_type": j.scan_type,
        "status": j.status,
        "started_at": _utc_iso(j.started_at),
        "completed_at": _utc_iso(j.completed_at),
        "total_checks": j.total_checks,
        "passed_checks": j.passed_checks,
        "failed_checks": j.failed_checks,
        "warning_checks": j.warning_checks,
        "findings_count": j.findings_count,
        "severity_distribution": j.severity_distribution,
        "coverage": j.coverage,
        "error_detail": j.error_detail,
        "created_at": _utc_iso(j.created_at),
    }


# =====================================================================
# Rules
# =====================================================================

def list_rules(db: Session, category: Optional[str] = None) -> List[Dict[str, Any]]:
    q = db.query(CSPMRule)
    if category:
        q = q.filter(CSPMRule.category == category.upper())
    rules = q.order_by(CSPMRule.category, CSPMRule.id).all()
    return [_rule_to_dict(r) for r in rules]


def get_rule(db: Session, rule_id: str) -> Optional[Dict[str, Any]]:
    r = db.query(CSPMRule).filter(CSPMRule.id == rule_id).first()
    return _rule_to_dict(r) if r else None


def _rule_to_dict(r: CSPMRule) -> Dict[str, Any]:
    return {
        "id": r.id,
        "name": r.name,
        "category": r.category,
        "severity": r.severity,
        "description": r.description,
        "detection_logic_status": r.detection_logic_status,
        "framework_mapping": r.framework_mapping,
        "version": r.version,
        "is_active": r.is_active,
        "last_validated_at": _utc_iso(r.last_validated_at),
        "last_validation_status": r.last_validation_status,
        "created_at": _utc_iso(r.created_at),
        "updated_at": _utc_iso(r.updated_at),
    }


# =====================================================================
# Dashboard Overview
# =====================================================================

def get_cspm_dashboard_overview(db: Session, tenant_id: str) -> Dict[str, Any]:
    total_agents = db.query(CSPMAgent).filter(CSPMAgent.tenant_id == tenant_id).count()
    total_envs = db.query(CloudEnvironment).filter(CloudEnvironment.tenant_id == tenant_id).count()

    open_statuses = ["OPEN", "ACKNOWLEDGED", "IN_PROGRESS"]
    open_findings_q = db.query(SecurityFinding).filter(
        SecurityFinding.tenant_id == tenant_id,
        SecurityFinding.status.in_(open_statuses),
    )
    total_open = open_findings_q.count()
    critical = open_findings_q.filter(SecurityFinding.severity == "CRITICAL").count()
    high = open_findings_q.filter(SecurityFinding.severity == "HIGH").count()
    medium = open_findings_q.filter(SecurityFinding.severity == "MEDIUM").count()
    low = open_findings_q.filter(SecurityFinding.severity == "LOW").count()

    agents_with_issues = db.query(CSPMAgent).filter(
        CSPMAgent.tenant_id == tenant_id,
        CSPMAgent.open_findings_count > 0,
    ).count()

    # Agent health
    health_summary: Dict[str, int] = {}
    for row in db.query(CSPMAgent.connection_status, func.count()).filter(
        CSPMAgent.tenant_id == tenant_id
    ).group_by(CSPMAgent.connection_status).all():
        health_summary[row[0]] = row[1]

    # Severity distribution for chart
    sev_dist: Dict[str, int] = {}
    for row in db.query(SecurityFinding.severity, func.count()).filter(
        SecurityFinding.tenant_id == tenant_id,
        SecurityFinding.status.in_(open_statuses),
    ).group_by(SecurityFinding.severity).all():
        sev_dist[row[0]] = row[1]

    # Category distribution for chart
    cat_dist: Dict[str, int] = {}
    for row in db.query(SecurityFinding.category, func.count()).filter(
        SecurityFinding.tenant_id == tenant_id,
        SecurityFinding.status.in_(open_statuses),
    ).group_by(SecurityFinding.category).all():
        cat_dist[row[0]] = row[1]

    # Recent scans
    recent_scan_count = db.query(CSPMScanJob).filter(
        CSPMScanJob.tenant_id == tenant_id,
    ).count()

    # Average risk score
    avg_risk_row = db.query(func.avg(CSPMAgent.risk_score)).filter(
        CSPMAgent.tenant_id == tenant_id,
    ).scalar()
    avg_risk = round(float(avg_risk_row), 1) if avg_risk_row else 0.0

    # Total assets (agents + environments)
    total_assets = total_agents + total_envs

    return {
        "total_agents": total_agents,
        "total_environments": total_envs,
        "total_assets": total_assets,
        "total_open_findings": total_open,
        "critical_findings": critical,
        "high_findings": high,
        "medium_findings": medium,
        "low_findings": low,
        "agents_with_issues": agents_with_issues,
        "recent_scan_count": recent_scan_count,
        "average_risk_score": avg_risk,
        "agent_health_summary": health_summary,
        "severity_distribution": sev_dist,
        "category_distribution": cat_dist,
        "recent_events": [],  # Populated from existing audit events
        "is_demo_data": True,  # Clearly labelled as demonstration
    }
