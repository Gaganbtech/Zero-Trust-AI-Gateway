import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.models import CSPMScanRecord
from app.cspm.schemas import CSPMScanSummary, PostureCheckResult, CSPMStatus
from app.cspm.scanner import run_cspm_scan


def execute_and_store_scan(db: Session, cloud_environment: str = "AWS / EKS Production") -> CSPMScanSummary:
    """Runs a cloud AI posture scan and stores the results in the database."""
    summary = run_cspm_scan(cloud_environment=cloud_environment)
    
    findings_dicts = [f.model_dump() for f in summary.findings]
    record = CSPMScanRecord(
        id=summary.scan_id,
        timestamp=datetime.now(timezone.utc),
        cloud_environment=summary.cloud_environment,
        compliance_score=summary.compliance_score,
        total_checks=summary.total_checks,
        passed_checks=summary.passed_checks,
        failed_checks=summary.failed_checks,
        warning_checks=summary.warning_checks,
        critical_findings=summary.critical_findings,
        findings_json=json.dumps(findings_dicts),
        category_scores_json=json.dumps(summary.category_scores)
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return summary


def get_latest_scan(db: Session) -> CSPMScanSummary:
    """Retrieves the latest posture scan from the database, or runs one if none exist."""
    record = db.query(CSPMScanRecord).order_by(desc(CSPMScanRecord.timestamp)).first()
    if not record:
        return execute_and_store_scan(db)
    
    findings = [PostureCheckResult(**f) for f in record.get_findings()]
    return CSPMScanSummary(
        scan_id=record.id,
        timestamp=record.timestamp.isoformat() if record.timestamp else datetime.now(timezone.utc).isoformat(),
        cloud_environment=record.cloud_environment,
        compliance_score=record.compliance_score,
        total_checks=record.total_checks,
        passed_checks=record.passed_checks,
        failed_checks=record.failed_checks,
        warning_checks=record.warning_checks,
        critical_findings=record.critical_findings,
        high_findings=sum(1 for f in findings if f.severity == "HIGH" and f.status == "FAIL"),
        medium_findings=sum(1 for f in findings if f.severity == "MEDIUM" and f.status == "FAIL"),
        low_findings=sum(1 for f in findings if f.severity == "LOW" and f.status == "FAIL"),
        category_scores=record.get_category_scores(),
        findings=findings
    )


def get_scan_history(db: Session, limit: int = 10) -> List[Dict[str, Any]]:
    """Retrieves historical posture scan summaries."""
    records = db.query(CSPMScanRecord).order_by(desc(CSPMScanRecord.timestamp)).limit(limit).all()
    history = []
    for r in records:
        history.append({
            "scan_id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else "",
            "cloud_environment": r.cloud_environment,
            "compliance_score": r.compliance_score,
            "total_checks": r.total_checks,
            "passed_checks": r.passed_checks,
            "failed_checks": r.failed_checks,
            "critical_findings": r.critical_findings
        })
    return history


def get_active_misconfigurations(db: Session) -> List[PostureCheckResult]:
    """Returns failing or warning checks from the latest scan."""
    latest = get_latest_scan(db)
    return [f for f in latest.findings if f.status != CSPMStatus.PASS]
