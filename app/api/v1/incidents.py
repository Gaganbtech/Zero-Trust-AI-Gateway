from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.database.models import Incident, User
from app.schemas.gateway import IncidentNoteRequest, IncidentStatusRequest
from app.auth.dependencies import get_current_user
from app.auth.rbac import Role

router = APIRouter(prefix="/api/v1/incidents", tags=["Incident Response"])


@router.get("", summary="List Security Incidents")
async def list_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Lists security incidents correlated from runtime violation events."""
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status.upper())
    if severity:
        query = query.filter(Incident.severity == severity.upper())

    incidents = query.order_by(Incident.created_at.desc()).all()
    return [
        {
            "id": inc.id,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "agent_id": inc.agent_id,
            "tenant_id": inc.tenant_id,
            "rule_name": inc.rule_name,
            "description": inc.description,
            "evidence_event_ids": inc.evidence_event_ids,
            "remediation_guidance": inc.remediation_guidance,
            "analyst_notes": inc.analyst_notes,
            "assigned_to": inc.assigned_to,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
        }
        for inc in incidents
    ]


@router.get("/{incident_id}", summary="Get Incident Details")
async def get_incident(
    incident_id: str,
    db: Session = Depends(get_db)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return {
        "id": inc.id,
        "title": inc.title,
        "severity": inc.severity,
        "status": inc.status,
        "agent_id": inc.agent_id,
        "tenant_id": inc.tenant_id,
        "rule_name": inc.rule_name,
        "description": inc.description,
        "evidence_event_ids": inc.evidence_event_ids,
        "remediation_guidance": inc.remediation_guidance,
        "analyst_notes": inc.analyst_notes,
        "assigned_to": inc.assigned_to,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
    }


@router.post("/{incident_id}/notes", summary="Add Analyst Notes")
async def add_incident_notes(
    incident_id: str,
    payload: IncidentNoteRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    new_note = f"[{current_user.username}]: {payload.notes}"
    if inc.analyst_notes:
        inc.analyst_notes += "\n" + new_note
    else:
        inc.analyst_notes = new_note

    db.commit()
    db.refresh(inc)
    return {"message": "Analyst note added successfully", "incident_id": inc.id, "analyst_notes": inc.analyst_notes}


@router.post("/{incident_id}/status", summary="Update Incident Status")
async def update_incident_status(
    incident_id: str,
    payload: IncidentStatusRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    inc.status = payload.status
    inc.assigned_to = current_user.username
    db.commit()
    db.refresh(inc)
    return {"message": f"Incident status updated to {payload.status}", "incident_id": inc.id, "status": inc.status}
