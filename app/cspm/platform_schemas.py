"""
LUME AI-CSPM Platform — API Schemas for CSPM Platform Resources

Provider-neutral request/response schemas for cloud environments,
AI agents, security findings, scans, and rules.
"""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"


class ConnectionStatus(str, Enum):
    NOT_CONNECTED = "NOT_CONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    ERROR = "ERROR"
    DISCONNECTED = "DISCONNECTED"


class HealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"


class AgentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    SUSPENDED = "SUSPENDED"
    DECOMMISSIONED = "DECOMMISSIONED"


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class FindingCategory(str, Enum):
    CLOUD_CONFIG = "CLOUD_CONFIG"
    IAM_PERMISSIONS = "IAM_PERMISSIONS"
    AGENT_CONFIG = "AGENT_CONFIG"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK_RESISTANCE = "JAILBREAK_RESISTANCE"
    DATA_LEAKAGE = "DATA_LEAKAGE"
    MCP_TOOL_SECURITY = "MCP_TOOL_SECURITY"
    NETWORK_SSRF = "NETWORK_SSRF"
    INSECURE_INTEGRATION = "INSECURE_INTEGRATION"
    LOGGING_AUDIT = "LOGGING_AUDIT"
    CROSS_TENANT_ISOLATION = "CROSS_TENANT_ISOLATION"
    VULNERABLE_DEPENDENCIES = "VULNERABLE_DEPENDENCIES"


class ScanType(str, Enum):
    CLOUD_POSTURE = "CLOUD_POSTURE"
    AGENT_SECURITY = "AGENT_SECURITY"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    FULL_ASSESSMENT = "FULL_ASSESSMENT"


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class DetectionLogicStatus(str, Enum):
    IMPLEMENTED = "IMPLEMENTED"
    PARTIAL = "PARTIAL"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"


class FindingConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ---------------------------------------------------------------------------
# Cloud Environment Schemas
# ---------------------------------------------------------------------------
class CloudEnvironmentCreate(BaseModel):
    provider: CloudProvider
    name: str = Field(min_length=1, max_length=200)
    account_id: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = None
    region: Optional[str] = Field(default=None, max_length=100)


class CloudEnvironmentResponse(BaseModel):
    id: str
    tenant_id: str
    provider: str
    account_id: Optional[str]
    name: str
    description: Optional[str]
    region: Optional[str]
    connection_status: str
    last_sync_at: Optional[str]
    health_status: str
    connector_version: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]


class CloudEnvironmentUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    description: Optional[str] = None
    region: Optional[str] = Field(default=None, max_length=100)


# ---------------------------------------------------------------------------
# AI Agent Schemas
# ---------------------------------------------------------------------------
class CSPMAgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    environment_id: Optional[str] = None
    cloud_provider: Optional[CloudProvider] = None
    cloud_account_id: Optional[str] = None
    deployment_environment: str = Field(default="development", pattern="^(development|staging|production)$")
    region: Optional[str] = None
    framework: Optional[str] = None
    model_provider: Optional[str] = None
    model_name: Optional[str] = None
    description: Optional[str] = None
    tools: List[str] = Field(default_factory=list)
    mcp_servers: List[str] = Field(default_factory=list)


class CSPMAgentResponse(BaseModel):
    id: str
    name: str
    tenant_id: str
    environment_id: Optional[str]
    cloud_provider: Optional[str]
    cloud_account_id: Optional[str]
    deployment_environment: str
    region: Optional[str]
    framework: Optional[str]
    model_provider: Optional[str]
    model_name: Optional[str]
    description: Optional[str]
    tools: List[str]
    mcp_servers: List[str]
    registration_source: str
    status: str
    connection_status: str
    risk_score: float
    open_findings_count: int
    critical_findings_count: int
    high_findings_count: int
    last_seen_at: Optional[str]
    last_scan_at: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]


class AgentHeartbeatRequest(BaseModel):
    status: Optional[str] = Field(default="ACTIVE", pattern="^(ACTIVE|INACTIVE)$")
    metadata: Optional[Dict[str, Any]] = None


class AgentHeartbeatResponse(BaseModel):
    agent_id: str
    acknowledged: bool
    server_time: str


# ---------------------------------------------------------------------------
# Security Finding Schemas
# ---------------------------------------------------------------------------
class FindingCreate(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1)
    category: FindingCategory
    severity: FindingSeverity
    confidence: FindingConfidence = FindingConfidence.HIGH
    rule_id: Optional[str] = None
    agent_id: Optional[str] = None
    environment_id: Optional[str] = None
    resource_id: Optional[str] = None
    cloud_provider: Optional[CloudProvider] = None
    detection_source: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    technical_detail: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    compliance_frameworks: List[str] = Field(default_factory=list)


class FindingResponse(BaseModel):
    id: str
    rule_id: Optional[str]
    tenant_id: str
    agent_id: Optional[str]
    environment_id: Optional[str]
    resource_id: Optional[str]
    title: str
    description: str
    category: str
    severity: str
    confidence: str
    cloud_provider: Optional[str]
    detection_source: Optional[str]
    evidence: Dict[str, Any]
    technical_detail: Optional[str]
    impact: Optional[str]
    remediation: Optional[str]
    compliance_frameworks: List[str]
    status: str
    first_seen_at: Optional[str]
    last_seen_at: Optional[str]
    resolved_at: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    notes: Optional[str] = None


class FindingHistoryResponse(BaseModel):
    id: int
    finding_id: str
    previous_status: Optional[str]
    new_status: str
    changed_by: Optional[str]
    notes: Optional[str]
    timestamp: Optional[str]


# ---------------------------------------------------------------------------
# Scan Job Schemas
# ---------------------------------------------------------------------------
class ScanJobCreate(BaseModel):
    target_agent_id: Optional[str] = None
    target_environment_id: Optional[str] = None
    scan_type: ScanType = ScanType.CLOUD_POSTURE


class ScanJobResponse(BaseModel):
    id: str
    tenant_id: str
    target_agent_id: Optional[str]
    target_environment_id: Optional[str]
    scan_type: str
    status: str
    started_at: Optional[str]
    completed_at: Optional[str]
    total_checks: int
    passed_checks: int
    failed_checks: int
    warning_checks: int
    findings_count: int
    severity_distribution: Dict[str, int]
    coverage: Dict[str, Any]
    error_detail: Optional[str]
    created_at: Optional[str]


# ---------------------------------------------------------------------------
# CSPM Rule Schemas
# ---------------------------------------------------------------------------
class CSPMRuleResponse(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    description: str
    detection_logic_status: str
    framework_mapping: List[str]
    version: str
    is_active: bool
    last_validated_at: Optional[str]
    last_validation_status: Optional[str]
    created_at: Optional[str]
    updated_at: Optional[str]


# ---------------------------------------------------------------------------
# Dashboard Overview Schemas
# ---------------------------------------------------------------------------
class CSPMDashboardOverview(BaseModel):
    total_agents: int
    total_environments: int
    total_assets: int
    total_open_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    agents_with_issues: int
    recent_scan_count: int
    average_risk_score: float
    agent_health_summary: Dict[str, int]  # {CONNECTED: 2, DISCONNECTED: 1, ...}
    severity_distribution: Dict[str, int]
    category_distribution: Dict[str, int]
    recent_events: List[Dict[str, Any]]
    is_demo_data: bool = True  # Clearly label demonstration data
