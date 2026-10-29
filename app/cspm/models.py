"""
LUME AI-CSPM Platform — Provider-Neutral Data Models

These models support AWS, Azure, and GCP integrations without schema changes.
All models enforce tenant isolation via tenant_id foreign key alignment.
"""
import json
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, Float, DateTime, Index, ForeignKey
)
from app.database.session import Base


def utc_now():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Cloud Environment Registry
# ---------------------------------------------------------------------------
class CloudEnvironment(Base):
    """
    Provider-neutral cloud environment record.
    Represents an AWS account, Azure subscription, or GCP project.
    """
    __tablename__ = "cloud_environments"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(100), index=True, nullable=False)
    provider = Column(String(20), index=True, nullable=False)  # AWS, AZURE, GCP
    account_id = Column(String(200), nullable=True)  # AWS Account ID, Azure Subscription, GCP Project
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    region = Column(String(100), nullable=True)
    connection_status = Column(String(30), index=True, default="NOT_CONNECTED")
    # NOT_CONNECTED, CONNECTING, CONNECTED, ERROR, DISCONNECTED
    last_sync_at = Column(DateTime(timezone=True), nullable=True)
    health_status = Column(String(30), default="UNKNOWN")  # HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN
    connector_version = Column(String(50), nullable=True)
    config_json = Column(Text, default="{}")  # Provider-specific non-secret config
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    __table_args__ = (
        Index("idx_cloud_env_tenant_provider", "tenant_id", "provider"),
    )

    @property
    def config(self):
        try:
            return json.loads(self.config_json)
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# AI Agent (CSPM-Extended) — extends existing AgentRegistryItem concept
# ---------------------------------------------------------------------------
class CSPMAgent(Base):
    """
    AI Agent record enriched with cloud deployment context,
    framework metadata, and risk scoring for the CSPM platform.

    This is separate from the existing AgentRegistryItem to avoid
    breaking existing gateway authentication flows.
    """
    __tablename__ = "cspm_agents"

    id = Column(String(100), primary_key=True)
    name = Column(String(200), nullable=False)
    tenant_id = Column(String(100), index=True, nullable=False)
    environment_id = Column(String(64), ForeignKey("cloud_environments.id"), nullable=True, index=True)
    cloud_provider = Column(String(20), nullable=True)  # AWS, AZURE, GCP
    cloud_account_id = Column(String(200), nullable=True)
    deployment_environment = Column(String(50), default="development")  # development, staging, production
    region = Column(String(100), nullable=True)
    framework = Column(String(100), nullable=True)  # langchain, crewai, autogen, custom
    model_provider = Column(String(100), nullable=True)  # openai, anthropic, google, etc.
    model_name = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    tools_json = Column(Text, default="[]")  # Connected tools list
    mcp_servers_json = Column(Text, default="[]")  # Connected MCP servers
    registration_source = Column(String(50), default="manual")  # manual, api, connector, demo
    status = Column(String(30), index=True, default="ACTIVE")
    # ACTIVE, INACTIVE, SUSPENDED, DECOMMISSIONED
    connection_status = Column(String(30), default="UNKNOWN")
    # CONNECTED, DISCONNECTED, UNKNOWN, ERROR
    risk_score = Column(Float, default=0.0)  # 0-100 composite risk score
    open_findings_count = Column(Integer, default=0)
    critical_findings_count = Column(Integer, default=0)
    high_findings_count = Column(Integer, default=0)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    last_scan_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    __table_args__ = (
        Index("idx_cspm_agent_tenant", "tenant_id"),
        Index("idx_cspm_agent_provider", "cloud_provider"),
        Index("idx_cspm_agent_status", "status"),
    )

    @property
    def tools(self):
        try:
            return json.loads(self.tools_json)
        except Exception:
            return []

    @property
    def mcp_servers(self):
        try:
            return json.loads(self.mcp_servers_json)
        except Exception:
            return []


# ---------------------------------------------------------------------------
# Security Finding
# ---------------------------------------------------------------------------
class SecurityFinding(Base):
    """
    Normalized security finding from any detection source:
    cloud posture scans, prompt injection tests, manual assessments, etc.
    """
    __tablename__ = "security_findings"

    id = Column(String(64), primary_key=True)
    rule_id = Column(String(100), index=True, nullable=True)
    tenant_id = Column(String(100), index=True, nullable=False)
    agent_id = Column(String(100), ForeignKey("cspm_agents.id"), nullable=True, index=True)
    environment_id = Column(String(64), ForeignKey("cloud_environments.id"), nullable=True, index=True)
    resource_id = Column(String(300), nullable=True)

    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(100), index=True, nullable=False)
    # CLOUD_CONFIG, IAM_PERMISSIONS, AGENT_CONFIG, PROMPT_INJECTION,
    # JAILBREAK_RESISTANCE, DATA_LEAKAGE, MCP_TOOL_SECURITY,
    # NETWORK_SSRF, INSECURE_INTEGRATION, LOGGING_AUDIT,
    # CROSS_TENANT_ISOLATION, VULNERABLE_DEPENDENCIES

    severity = Column(String(20), index=True, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(String(20), default="HIGH")  # HIGH, MEDIUM, LOW
    cloud_provider = Column(String(20), nullable=True)

    detection_source = Column(String(100), nullable=True)  # cspm_scanner, agent_report, manual, connector
    evidence_json = Column(Text, default="{}")
    technical_detail = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    compliance_frameworks_json = Column(Text, default="[]")

    status = Column(String(30), index=True, default="OPEN")
    # OPEN, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, FALSE_POSITIVE

    first_seen_at = Column(DateTime(timezone=True), default=utc_now)
    last_seen_at = Column(DateTime(timezone=True), default=utc_now)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    __table_args__ = (
        Index("idx_finding_tenant_severity", "tenant_id", "severity"),
        Index("idx_finding_tenant_status", "tenant_id", "status"),
        Index("idx_finding_category", "category"),
        Index("idx_finding_agent", "agent_id"),
    )

    @property
    def evidence(self):
        try:
            return json.loads(self.evidence_json)
        except Exception:
            return {}

    @property
    def compliance_frameworks(self):
        try:
            return json.loads(self.compliance_frameworks_json)
        except Exception:
            return []


# ---------------------------------------------------------------------------
# Finding Status History
# ---------------------------------------------------------------------------
class FindingHistory(Base):
    """Tracks status transitions for a security finding."""
    __tablename__ = "finding_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(String(64), ForeignKey("security_findings.id"), index=True, nullable=False)
    previous_status = Column(String(30), nullable=True)
    new_status = Column(String(30), nullable=False)
    changed_by = Column(String(100), nullable=True)  # username or system
    notes = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now)


# ---------------------------------------------------------------------------
# CSPM Scan Job
# ---------------------------------------------------------------------------
class CSPMScanJob(Base):
    """
    Tracks individual scan executions against agents or environments.
    Supports future cloud posture scans and AI-agent security assessments.
    """
    __tablename__ = "cspm_scan_jobs"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(100), index=True, nullable=False)
    target_agent_id = Column(String(100), ForeignKey("cspm_agents.id"), nullable=True)
    target_environment_id = Column(String(64), ForeignKey("cloud_environments.id"), nullable=True)
    scan_type = Column(String(50), nullable=False)
    # CLOUD_POSTURE, AGENT_SECURITY, PROMPT_INJECTION, FULL_ASSESSMENT

    status = Column(String(30), index=True, default="PENDING")
    # PENDING, RUNNING, COMPLETED, FAILED, CANCELLED

    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    warning_checks = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    severity_distribution_json = Column(Text, default="{}")
    coverage_json = Column(Text, default="{}")  # Which categories were checked
    error_detail = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        Index("idx_scan_job_tenant", "tenant_id"),
        Index("idx_scan_job_status", "status"),
    )

    @property
    def severity_distribution(self):
        try:
            return json.loads(self.severity_distribution_json)
        except Exception:
            return {}

    @property
    def coverage(self):
        try:
            return json.loads(self.coverage_json)
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# CSPM Security Rule
# ---------------------------------------------------------------------------
class CSPMRule(Base):
    """
    Security rule definition used by scanners and for compliance mapping.
    """
    __tablename__ = "cspm_rules"

    id = Column(String(100), primary_key=True)
    name = Column(String(200), nullable=False)
    category = Column(String(100), index=True, nullable=False)
    severity = Column(String(20), index=True, nullable=False)
    description = Column(Text, nullable=False)
    detection_logic_status = Column(String(30), default="NOT_IMPLEMENTED")
    # IMPLEMENTED, PARTIAL, NOT_IMPLEMENTED
    framework_mapping_json = Column(Text, default="[]")  # NIST, CIS, OWASP, MITRE
    version = Column(String(20), default="1.0.0")
    is_active = Column(Boolean, default=True)
    last_validated_at = Column(DateTime(timezone=True), nullable=True)
    last_validation_status = Column(String(30), nullable=True)  # PASS, FAIL, ERROR, NOT_RUN
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    @property
    def framework_mapping(self):
        try:
            return json.loads(self.framework_mapping_json)
        except Exception:
            return []
