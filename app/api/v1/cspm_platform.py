"""
LUME AI-CSPM Platform — API Routes

Provides REST endpoints for CSPM platform management:
- Cloud environments
- Agent inventory and registration
- Security findings with lifecycle
- Scan history
- CSPM rules
- Dashboard overview
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.cspm.platform_service import (
    create_cloud_environment, list_cloud_environments, get_cloud_environment,
    update_cloud_environment, delete_cloud_environment,
    register_agent, list_agents, get_agent, agent_heartbeat, get_agent_posture,
    create_finding, list_findings, get_finding, update_finding_status,
    ingest_agent_findings,
    create_scan_job, list_scan_jobs, get_scan_job,
    list_rules, get_rule,
    get_cspm_dashboard_overview,
)
from app.cspm.platform_schemas import (
    CloudEnvironmentCreate, CloudEnvironmentUpdate,
    CSPMAgentCreate, AgentHeartbeatRequest,
    FindingCreate, FindingStatusUpdate,
    ScanJobCreate,
    FindingSeverity, FindingStatus, FindingCategory,
)

router = APIRouter(prefix="/api/v1/cspm/platform", tags=["AI-CSPM Platform"])

# Default tenant for development; in production, derived from auth
DEFAULT_TENANT = "tenant-alpha"


# =====================================================================
# Dashboard Overview
# =====================================================================

@router.get("/overview", summary="CSPM Dashboard Overview")
async def cspm_overview(db: Session = Depends(get_db)):
    """
    Returns aggregated CSPM platform metrics for the dashboard.
    All values come from the backend database.
    Demonstration data is clearly labelled.
    """
    return get_cspm_dashboard_overview(db, DEFAULT_TENANT)


# =====================================================================
# Cloud Environments
# =====================================================================

@router.get("/environments", summary="List Cloud Environments")
async def api_list_environments(db: Session = Depends(get_db)):
    """Lists all registered cloud environments for the tenant."""
    return list_cloud_environments(db, DEFAULT_TENANT)


@router.post("/environments", summary="Register Cloud Environment", status_code=201)
async def api_create_environment(
    payload: CloudEnvironmentCreate,
    db: Session = Depends(get_db),
):
    """
    Register a new cloud environment.
    Connection status defaults to NOT_CONNECTED until a real connector is implemented.
    """
    return create_cloud_environment(
        db=db,
        tenant_id=DEFAULT_TENANT,
        provider=payload.provider.value,
        name=payload.name,
        account_id=payload.account_id,
        description=payload.description,
        region=payload.region,
    )


@router.get("/environments/{env_id}", summary="Get Cloud Environment")
async def api_get_environment(env_id: str, db: Session = Depends(get_db)):
    result = get_cloud_environment(db, env_id, DEFAULT_TENANT)
    if not result:
        raise HTTPException(status_code=404, detail="Cloud environment not found")
    return result


@router.patch("/environments/{env_id}", summary="Update Cloud Environment")
async def api_update_environment(
    env_id: str,
    payload: CloudEnvironmentUpdate,
    db: Session = Depends(get_db),
):
    result = update_cloud_environment(db, env_id, DEFAULT_TENANT, payload.model_dump(exclude_none=True))
    if not result:
        raise HTTPException(status_code=404, detail="Cloud environment not found")
    return result


@router.delete("/environments/{env_id}", summary="Delete Cloud Environment", status_code=204)
async def api_delete_environment(env_id: str, db: Session = Depends(get_db)):
    if not delete_cloud_environment(db, env_id, DEFAULT_TENANT):
        raise HTTPException(status_code=404, detail="Cloud environment not found")


# =====================================================================
# Agent Inventory & Registration
# =====================================================================

@router.get("/agents", summary="List CSPM Agents")
async def api_list_agents(
    status: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Lists all AI agents registered in the CSPM platform."""
    return list_agents(db, DEFAULT_TENANT, status=status, provider=provider)


@router.post("/agents/register", summary="Register AI Agent", status_code=201)
async def api_register_agent(
    payload: CSPMAgentCreate,
    db: Session = Depends(get_db),
):
    """
    Register a new AI agent for CSPM monitoring.
    For development: creates demonstration agents clearly labelled as such.
    For production: requires workload authentication (future phase).
    """
    return register_agent(
        db=db,
        tenant_id=DEFAULT_TENANT,
        name=payload.name,
        registration_source="demo",
        environment_id=payload.environment_id,
        cloud_provider=payload.cloud_provider.value if payload.cloud_provider else None,
        cloud_account_id=payload.cloud_account_id,
        deployment_environment=payload.deployment_environment,
        region=payload.region,
        framework=payload.framework,
        model_provider=payload.model_provider,
        model_name=payload.model_name,
        description=payload.description,
        tools=payload.tools,
        mcp_servers=payload.mcp_servers,
    )


@router.get("/agents/{agent_id}", summary="Get Agent Details")
async def api_get_agent(agent_id: str, db: Session = Depends(get_db)):
    result = get_agent(db, agent_id, DEFAULT_TENANT)
    if not result:
        raise HTTPException(status_code=404, detail="Agent not found")
    return result


@router.post("/agents/{agent_id}/heartbeat", summary="Agent Heartbeat")
async def api_agent_heartbeat(
    agent_id: str,
    payload: Optional[AgentHeartbeatRequest] = None,
    db: Session = Depends(get_db),
):
    """
    Record an agent heartbeat to update connection status and last-seen time.
    In production, this requires workload authentication.
    """
    from datetime import datetime, timezone
    if not agent_heartbeat(db, agent_id, DEFAULT_TENANT):
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "agent_id": agent_id,
        "acknowledged": True,
        "server_time": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/agents/{agent_id}/posture", summary="Get Agent Security Posture")
async def api_get_agent_posture(agent_id: str, db: Session = Depends(get_db)):
    """Returns the security posture summary for a specific agent."""
    result = get_agent_posture(db, agent_id, DEFAULT_TENANT)
    if not result:
        raise HTTPException(status_code=404, detail="Agent not found")
    return result


@router.post("/agents/{agent_id}/findings", summary="Ingest Agent Findings", status_code=201)
async def api_ingest_agent_findings(
    agent_id: str,
    findings: List[FindingCreate],
    db: Session = Depends(get_db),
):
    """
    Ingest security findings reported by an agent or trusted collector.
    Validates severity and category. Does not blindly trust submitted values.
    In production, this requires workload authentication.
    """
    # Verify agent exists
    if not get_agent(db, agent_id, DEFAULT_TENANT):
        raise HTTPException(status_code=404, detail="Agent not found")

    findings_data = [f.model_dump() for f in findings]
    return ingest_agent_findings(
        db=db,
        agent_id=agent_id,
        tenant_id=DEFAULT_TENANT,
        findings_data=findings_data,
        detection_source="agent_report",
    )


# =====================================================================
# Security Findings
# =====================================================================

@router.get("/findings", summary="List Security Findings")
async def api_list_findings(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    agent_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """
    List security findings with filtering and pagination.
    Supports filtering by severity, status, category, agent, and provider.
    """
    items, total = list_findings(
        db=db, tenant_id=DEFAULT_TENANT,
        severity=severity, status=status, category=category,
        agent_id=agent_id, provider=provider,
        limit=limit, offset=offset,
    )
    return {"findings": items, "total": total, "limit": limit, "offset": offset}


@router.post("/findings", summary="Create Security Finding", status_code=201)
async def api_create_finding(
    payload: FindingCreate,
    db: Session = Depends(get_db),
):
    """Create a new security finding."""
    return create_finding(
        db=db,
        tenant_id=DEFAULT_TENANT,
        title=payload.title,
        description=payload.description,
        category=payload.category.value,
        severity=payload.severity.value,
        confidence=payload.confidence.value if payload.confidence else "HIGH",
        rule_id=payload.rule_id,
        agent_id=payload.agent_id,
        environment_id=payload.environment_id,
        resource_id=payload.resource_id,
        cloud_provider=payload.cloud_provider.value if payload.cloud_provider else None,
        detection_source=payload.detection_source,
        evidence=payload.evidence or {},
        technical_detail=payload.technical_detail,
        impact=payload.impact,
        remediation=payload.remediation,
        compliance_frameworks=payload.compliance_frameworks,
    )


@router.get("/findings/{finding_id}", summary="Get Finding Details")
async def api_get_finding(finding_id: str, db: Session = Depends(get_db)):
    """Get detailed finding information including status history."""
    result = get_finding(db, finding_id, DEFAULT_TENANT)
    if not result:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@router.post("/findings/{finding_id}/status", summary="Update Finding Status")
async def api_update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db),
):
    """
    Update finding status through lifecycle:
    OPEN → ACKNOWLEDGED → IN_PROGRESS → RESOLVED
    Status changes are recorded in finding history.
    """
    result = update_finding_status(
        db=db,
        finding_id=finding_id,
        tenant_id=DEFAULT_TENANT,
        new_status=payload.status.value,
        changed_by="dashboard_user",
        notes=payload.notes,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


# =====================================================================
# Scan History
# =====================================================================

@router.get("/scans", summary="List Scan Jobs")
async def api_list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List CSPM scan job history with pagination."""
    items, total = list_scan_jobs(db, DEFAULT_TENANT, limit=limit, offset=offset)
    return {"scans": items, "total": total, "limit": limit, "offset": offset}


@router.post("/scans", summary="Create Scan Job", status_code=201)
async def api_create_scan(
    payload: ScanJobCreate,
    db: Session = Depends(get_db),
):
    """
    Create a new scan job.
    In this phase, scans are recorded but not executed against external systems.
    """
    return create_scan_job(
        db=db,
        tenant_id=DEFAULT_TENANT,
        scan_type=payload.scan_type.value,
        target_agent_id=payload.target_agent_id,
        target_environment_id=payload.target_environment_id,
    )


@router.get("/scans/{scan_id}", summary="Get Scan Job Details")
async def api_get_scan(scan_id: str, db: Session = Depends(get_db)):
    result = get_scan_job(db, scan_id, DEFAULT_TENANT)
    if not result:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return result


# =====================================================================
# CSPM Rules
# =====================================================================

@router.get("/rules", summary="List CSPM Security Rules")
async def api_list_rules(
    category: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """List all CSPM security rules with optional category filter."""
    return list_rules(db, category=category)


@router.get("/rules/{rule_id}", summary="Get Rule Details")
async def api_get_rule(rule_id: str, db: Session = Depends(get_db)):
    result = get_rule(db, rule_id)
    if not result:
        raise HTTPException(status_code=404, detail="Rule not found")
    return result
