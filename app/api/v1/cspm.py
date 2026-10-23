from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.cspm.schemas import (
    CSPMScanSummary,
    PostureCheckResult,
    CSPMSeverity,
    CSPMStatus
)
from app.cspm.service import (
    execute_and_store_scan,
    get_latest_scan,
    get_scan_history,
    get_active_misconfigurations
)

router = APIRouter(prefix="/api/v1/cspm", tags=["Cloud Security Posture Management (CSPM)"])


class TriggerScanRequest(BaseModel):
    cloud_environment: str = Field(default="AWS / EKS Production", description="Target cloud AI environment name")


@router.get("/summary", response_model=CSPMScanSummary, summary="Get Latest AI-CSPM Posture Summary")
def get_cspm_summary(db: Session = Depends(get_db)):
    """Retrieves the latest Cloud Security Posture Management evaluation for AI infrastructure."""
    return get_latest_scan(db)


@router.post("/scan", response_model=CSPMScanSummary, summary="Run On-Demand AI-CSPM Posture Scan")
def trigger_cspm_scan(req: Optional[TriggerScanRequest] = None, db: Session = Depends(get_db)):
    """Executes on-demand inspection across AI model endpoints, vector databases, IAM, and K8s posture."""
    cloud_env = req.cloud_environment if req else "AWS / EKS Production"
    return execute_and_store_scan(db, cloud_environment=cloud_env)


@router.get("/findings", response_model=List[PostureCheckResult], summary="List AI Cloud Misconfigurations")
def get_cspm_findings(
    status: Optional[CSPMStatus] = None,
    severity: Optional[CSPMSeverity] = None,
    db: Session = Depends(get_db)
):
    """Returns posture findings filtered by status or severity."""
    latest = get_latest_scan(db)
    findings = latest.findings
    if status:
        findings = [f for f in findings if f.status == status]
    if severity:
        findings = [f for f in findings if f.severity == severity]
    return findings


@router.get("/history", summary="AI-CSPM Scan History")
def get_cspm_history(limit: int = Query(default=10, le=50), db: Session = Depends(get_db)):
    """Returns chronological audit history of cloud AI posture evaluations."""
    return get_scan_history(db, limit=limit)
