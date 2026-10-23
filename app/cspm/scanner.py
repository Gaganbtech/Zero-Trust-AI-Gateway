import uuid
from datetime import datetime, timezone
from typing import Dict, List
from app.cspm.schemas import (
    CSPMScanSummary,
    PostureCheckResult,
    CSPMStatus,
    CSPMSeverity,
    CSPMCategory
)
from app.cspm.checks import ALL_CSPM_CHECKS


def run_cspm_scan(cloud_environment: str = "AWS / EKS Production") -> CSPMScanSummary:
    """Executes all AI-CSPM checks and generates a compliance posture summary."""
    findings: List[PostureCheckResult] = []
    
    for check_fn in ALL_CSPM_CHECKS:
        try:
            res = check_fn()
            findings.append(res)
        except Exception as e:
            findings.append(PostureCheckResult(
                check_id=f"ERR-{check_fn.__name__}",
                name=f"Check Execution Error: {check_fn.__name__}",
                category=CSPMCategory.AUDIT_GOVERNANCE,
                severity=CSPMSeverity.MEDIUM,
                status=CSPMStatus.WARN,
                description=f"Error during check execution: {str(e)}",
                resource_id="internal:scanner",
                remediation_command="# Review scanner logs",
                remediation_guidance="Check cloud provider credentials and network connectivity.",
                evidence={"error": str(e)}
            ))

    total = len(findings)
    passed = sum(1 for f in findings if f.status == CSPMStatus.PASS)
    failed = sum(1 for f in findings if f.status == CSPMStatus.FAIL)
    warnings = sum(1 for f in findings if f.status == CSPMStatus.WARN)

    crit = sum(1 for f in findings if f.severity == CSPMSeverity.CRITICAL and f.status == CSPMStatus.FAIL)
    high = sum(1 for f in findings if f.severity == CSPMSeverity.HIGH and f.status == CSPMStatus.FAIL)
    med = sum(1 for f in findings if f.severity == CSPMSeverity.MEDIUM and f.status == CSPMStatus.FAIL)
    low = sum(1 for f in findings if f.severity == CSPMSeverity.LOW and f.status == CSPMStatus.FAIL)

    # Calculate compliance score (0 - 100)
    if total > 0:
        base_score = ((passed + (0.5 * warnings)) / total) * 100.0
        # If critical failures exist, apply security penalty
        penalty = min(30.0, crit * 15.0)
        compliance_score = max(0.0, round(base_score - penalty, 1))
    else:
        compliance_score = 100.0

    # Calculate category pass rates
    category_scores: Dict[str, float] = {}
    for cat in CSPMCategory:
        cat_findings = [f for f in findings if f.category == cat]
        if cat_findings:
            cat_passed = sum(1 for f in cat_findings if f.status == CSPMStatus.PASS)
            category_scores[cat.value] = round((cat_passed / len(cat_findings)) * 100.0, 1)
        else:
            category_scores[cat.value] = 100.0

    return CSPMScanSummary(
        scan_id=f"cspm-{uuid.uuid4().hex[:8]}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        cloud_environment=cloud_environment,
        compliance_score=compliance_score,
        total_checks=total,
        passed_checks=passed,
        failed_checks=failed,
        warning_checks=warnings,
        critical_findings=crit,
        high_findings=high,
        medium_findings=med,
        low_findings=low,
        category_scores=category_scores,
        findings=findings
    )
