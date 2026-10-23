from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class CSPMSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CSPMStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


class CSPMCategory(str, Enum):
    MODEL_ENDPOINTS = "MODEL_ENDPOINTS"
    IAM_IDENTITY = "IAM_IDENTITY"
    STORAGE_VECTOR_DB = "STORAGE_VECTOR_DB"
    NETWORK_EGRESS = "NETWORK_EGRESS"
    CONTAINER_K8S = "CONTAINER_K8S"
    SUPPLY_CHAIN_AI = "SUPPLY_CHAIN_AI"
    AUDIT_GOVERNANCE = "AUDIT_GOVERNANCE"


class PostureCheckResult(BaseModel):
    check_id: str
    name: str
    category: CSPMCategory
    severity: CSPMSeverity
    status: CSPMStatus
    description: str
    resource_id: str
    compliance_frameworks: List[str] = Field(default_factory=lambda: ["NIST_AI_RMF", "CIS_KUBERNETES", "OWASP_TOP_10_LLM"])
    remediation_command: str
    remediation_guidance: str
    evidence: Optional[Dict[str, Any]] = None


class CSPMScanSummary(BaseModel):
    scan_id: str
    timestamp: str
    cloud_environment: str
    compliance_score: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    warning_checks: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    category_scores: Dict[str, float]
    findings: List[PostureCheckResult]
