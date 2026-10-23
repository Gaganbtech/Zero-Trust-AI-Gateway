import json
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, Float, DateTime, Index
)
from app.database.session import Base


def utc_now():
    return datetime.now(timezone.utc)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(String(32), index=True, nullable=False)
    correlation_id = Column(String(64), index=True, nullable=False)
    agent_id = Column(String(100), index=True, nullable=False)
    tenant_id = Column(String(100), index=True, nullable=False, default="default-tenant")
    tool = Column(String(100), index=True, nullable=False)
    operation = Column(String(50), nullable=False)
    resource = Column(String(200), nullable=True)
    destination = Column(String(500), nullable=False)
    decision = Column(String(10), index=True, nullable=False)  # ALLOW, BLOCK
    reason = Column(String(100), nullable=False)
    policy_version = Column(String(50), default="1.0.0")
    policy_source = Column(String(50), default="opa")  # opa, local_fallback, pre_check
    risk_level = Column(String(20), default="LOW")     # LOW, MEDIUM, HIGH, CRITICAL
    prompt_flagged = Column(Boolean, default=False)
    dlp_findings_json = Column(Text, default="[]")
    metadata_json = Column(Text, default="{}")
    execution_duration_ms = Column(Float, nullable=True)
    previous_event_hash = Column(String(64), nullable=True)
    tamper_chain_hash = Column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_audit_agent_timestamp", "agent_id", "timestamp"),
        Index("idx_audit_decision", "decision"),
    )

    @property
    def dlp_findings(self):
        try:
            return json.loads(self.dlp_findings_json)
        except Exception:
            return []

    @property
    def metadata_dict(self):
        try:
            return json.loads(self.metadata_json)
        except Exception:
            return {}


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(100), index=True, nullable=False, default="default-tenant")
    name = Column(String(150), nullable=False)
    email = Column(String(150), nullable=False)
    phone = Column(String(50), nullable=False)
    card_number = Column(String(50), nullable=False)
    account_balance = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class AgentRegistryItem(Base):
    __tablename__ = "agents"

    id = Column(String(100), primary_key=True)
    name = Column(String(150), nullable=False)
    tenant_id = Column(String(100), index=True, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(20), default="ACTIVE")  # ACTIVE, SUSPENDED, REVOKED
    allowed_tools_json = Column(Text, default="[]")
    scopes_json = Column(Text, default="[]")
    created_at = Column(DateTime(timezone=True), default=utc_now)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)

    @property
    def allowed_tools(self):
        try:
            return json.loads(self.allowed_tools_json)
        except Exception:
            return []

    @property
    def scopes(self):
        try:
            return json.loads(self.scopes_json)
        except Exception:
            return []


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True)
    title = Column(String(200), nullable=False)
    severity = Column(String(20), index=True, default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String(30), index=True, default="OPEN")     # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    agent_id = Column(String(100), index=True, nullable=False)
    tenant_id = Column(String(100), index=True, nullable=False)
    rule_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    evidence_event_ids_json = Column(Text, default="[]")
    remediation_guidance = Column(Text, nullable=False)
    analyst_notes = Column(Text, nullable=True)
    assigned_to = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    @property
    def evidence_event_ids(self):
        try:
            return json.loads(self.evidence_event_ids_json)
        except Exception:
            return []


class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(30), default="viewer")  # admin, analyst, auditor, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)


class PolicyRecord(Base):
    __tablename__ = "policies"

    id = Column(String(64), primary_key=True)
    name = Column(String(100), nullable=False)
    version = Column(String(30), nullable=False)
    rego_code = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    checksum = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class CSPMScanRecord(Base):
    __tablename__ = "cspm_scans"

    id = Column(String(64), primary_key=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now)
    cloud_environment = Column(String(100), default="AWS / EKS Production")
    compliance_score = Column(Float, nullable=False)
    total_checks = Column(Integer, default=0)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    warning_checks = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    findings_json = Column(Text, nullable=False)
    category_scores_json = Column(Text, nullable=False)

    def get_findings(self):
        try:
            return json.loads(self.findings_json)
        except Exception:
            return []

    def get_category_scores(self):
        try:
            return json.loads(self.category_scores_json)
        except Exception:
            return {}

