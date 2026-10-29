import json
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from app.database.session import engine, SessionLocal, Base
from app.database.models import Customer, AgentRegistryItem, User, PolicyRecord
from app.auth.security import hash_password


def init_database():
    """Initializes tables and seeds initial data if missing."""
    # Import CSPM models so their tables are created
    from app.cspm import models as cspm_models  # noqa: F401

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # 1. Seed Synthetic Customers if empty
        if db.query(Customer).count() == 0:
            customers = [
                Customer(
                    tenant_id="tenant-alpha",
                    name="Asha Rao",
                    email="asha.rao@example.com",
                    phone="+91 98765 43210",
                    card_number="4111111111111111",
                    account_balance=12500.50,
                ),
                Customer(
                    tenant_id="tenant-alpha",
                    name="Kiran Das",
                    email="kiran.das@example.com",
                    phone="+91 91234 56789",
                    card_number="5555555555554444",
                    account_balance=3400.00,
                ),
                Customer(
                    tenant_id="tenant-alpha",
                    name="Carlos Mendez",
                    email="carlos.m@example.org",
                    phone="+1 415 555 0192",
                    card_number="4000000000000002",
                    account_balance=8920.10,
                ),
                Customer(
                    tenant_id="tenant-beta",
                    name="Elena Rostova",
                    email="elena.r@finance.example",
                    phone="+44 20 7946 0912",
                    card_number="4222222222222",
                    account_balance=450000.00,
                ),
                Customer(
                    tenant_id="tenant-beta",
                    name="Taro Tanaka",
                    email="taro.tanaka@tokyo.example",
                    phone="+81 3 5555 0143",
                    card_number="4111111111111111",
                    account_balance=78000.00,
                ),
            ]
            db.add_all(customers)

        # 2. Seed Registered Agents if empty
        if db.query(AgentRegistryItem).count() == 0:
            agents = [
                AgentRegistryItem(
                    id="demo-agent",
                    name="Deterministic Local Demo Agent",
                    tenant_id="tenant-alpha",
                    description="Standard local demo agent with read-only access to tenant-alpha customer records.",
                    status="ACTIVE",
                    allowed_tools_json=json.dumps(["db_query", "weather", "safe_http"]),
                    scopes_json=json.dumps(["customer:read", "weather:read", "http:egress"]),
                ),
                AgentRegistryItem(
                    id="agent-analytics-01",
                    name="Tenant-Alpha Analytics Agent",
                    tenant_id="tenant-alpha",
                    description="Production data warehouse analytics agent for tenant-alpha.",
                    status="ACTIVE",
                    allowed_tools_json=json.dumps(["db_query"]),
                    scopes_json=json.dumps(["customer:read"]),
                ),
                AgentRegistryItem(
                    id="agent-beta-support",
                    name="Tenant-Beta Support Agent",
                    tenant_id="tenant-beta",
                    description="Customer support automation agent strictly bound to tenant-beta.",
                    status="ACTIVE",
                    allowed_tools_json=json.dumps(["db_query", "weather"]),
                    scopes_json=json.dumps(["customer:read", "weather:read"]),
                ),
                AgentRegistryItem(
                    id="agent-suspended-99",
                    name="Compromised Suspended Agent",
                    tenant_id="tenant-alpha",
                    description="Agent quarantined due to suspicious automated tool invocation behavior.",
                    status="SUSPENDED",
                    allowed_tools_json=json.dumps([]),
                    scopes_json=json.dumps([]),
                ),
            ]
            db.add_all(agents)

        # 3. Seed Operator Dashboard Users if empty
        if db.query(User).count() == 0:
            users = [
                User(
                    id="user-admin-01",
                    username="admin",
                    hashed_password=hash_password("AdminSecure2026!"),
                    role="admin",
                    is_active=True,
                ),
                User(
                    id="user-analyst-01",
                    username="analyst",
                    hashed_password=hash_password("AnalystSecure2026!"),
                    role="analyst",
                    is_active=True,
                ),
                User(
                    id="user-auditor-01",
                    username="auditor",
                    hashed_password=hash_password("AuditorSecure2026!"),
                    role="auditor",
                    is_active=True,
                ),
                User(
                    id="user-viewer-01",
                    username="viewer",
                    hashed_password=hash_password("ViewerSecure2026!"),
                    role="viewer",
                    is_active=True,
                ),
            ]
            db.add_all(users)

        # 4. Seed Active Rego Policy Record if empty
        if db.query(PolicyRecord).count() == 0:
            rego_path = Path(__file__).resolve().parent.parent.parent / "policies" / "agent.rego"
            if rego_path.exists():
                rego_code = rego_path.read_text(encoding="utf-8")
            else:
                rego_code = "package ai_gateway\n\ndefault allow := false\n"
            
            checksum = hashlib.sha256(rego_code.encode("utf-8")).hexdigest()
            policy_record = PolicyRecord(
                id="policy-rego-v1",
                name="AI Gateway Zero-Trust Runtime Policy",
                version="1.0.0",
                rego_code=rego_code,
                is_active=True,
                checksum=checksum,
            )
            db.add(policy_record)

        # 5. Seed CSPM Platform Demo Data
        _seed_cspm_demo_data(db)

        db.commit()
    finally:
        db.close()


def _seed_cspm_demo_data(db):
    """
    Seeds demonstration CSPM data: environments, agents, findings, scans, and rules.
    All demo data is clearly labelled with registration_source='demo'.
    """
    from app.cspm.models import (
        CloudEnvironment, CSPMAgent, SecurityFinding, FindingHistory,
        CSPMScanJob, CSPMRule,
    )

    now = datetime.now(timezone.utc)

    # --- Cloud Environments (NOT_CONNECTED by design) ---
    if db.query(CloudEnvironment).count() == 0:
        envs = [
            CloudEnvironment(
                id="env-aws-demo-01",
                tenant_id="tenant-alpha",
                provider="AWS",
                account_id="123456789012",
                name="AWS Production (us-east-1)",
                description="[DEMO] Primary AWS account for AI agent workloads. Not connected — awaiting Phase 2 integration.",
                region="us-east-1",
                connection_status="NOT_CONNECTED",
                health_status="UNKNOWN",
            ),
            CloudEnvironment(
                id="env-azure-demo-01",
                tenant_id="tenant-alpha",
                provider="AZURE",
                account_id="sub-a1b2c3d4-e5f6",
                name="Azure AI Staging (westeurope)",
                description="[DEMO] Azure subscription for staging AI agent deployments. Not connected — awaiting Phase 2 integration.",
                region="westeurope",
                connection_status="NOT_CONNECTED",
                health_status="UNKNOWN",
            ),
            CloudEnvironment(
                id="env-gcp-demo-01",
                tenant_id="tenant-alpha",
                provider="GCP",
                account_id="lume-ai-agents-prod",
                name="GCP AI Development (us-central1)",
                description="[DEMO] GCP project for AI agent development. Not connected — awaiting Phase 2 integration.",
                region="us-central1",
                connection_status="NOT_CONNECTED",
                health_status="UNKNOWN",
            ),
        ]
        db.add_all(envs)
        db.flush()

    # --- CSPM Agents (demo, clearly labelled) ---
    if db.query(CSPMAgent).count() == 0:
        agents = [
            CSPMAgent(
                id="cspm-agent-aws-rag",
                name="AWS RAG Assistant",
                tenant_id="tenant-alpha",
                environment_id="env-aws-demo-01",
                cloud_provider="AWS",
                cloud_account_id="123456789012",
                deployment_environment="production",
                region="us-east-1",
                framework="langchain",
                model_provider="openai",
                model_name="gpt-4o",
                description="[DEMO] RAG-based document Q&A agent deployed on ECS Fargate. Demonstration data only.",
                tools_json=json.dumps(["document_search", "db_query", "web_scrape"]),
                mcp_servers_json=json.dumps(["mcp-document-server"]),
                registration_source="demo",
                status="ACTIVE",
                connection_status="DISCONNECTED",
                risk_score=72.0,
                open_findings_count=5,
                critical_findings_count=1,
                high_findings_count=2,
                last_seen_at=now - timedelta(hours=2),
            ),
            CSPMAgent(
                id="cspm-agent-azure-support",
                name="Azure Customer Support Bot",
                tenant_id="tenant-alpha",
                environment_id="env-azure-demo-01",
                cloud_provider="AZURE",
                cloud_account_id="sub-a1b2c3d4-e5f6",
                deployment_environment="staging",
                region="westeurope",
                framework="semantic-kernel",
                model_provider="openai",
                model_name="gpt-4o-mini",
                description="[DEMO] Customer support chatbot deployed on Azure Container Apps. Demonstration data only.",
                tools_json=json.dumps(["ticket_lookup", "knowledge_base", "email_send"]),
                mcp_servers_json=json.dumps([]),
                registration_source="demo",
                status="ACTIVE",
                connection_status="DISCONNECTED",
                risk_score=45.0,
                open_findings_count=3,
                critical_findings_count=0,
                high_findings_count=1,
            ),
            CSPMAgent(
                id="cspm-agent-gcp-analyst",
                name="GCP Data Analysis Agent",
                tenant_id="tenant-alpha",
                environment_id="env-gcp-demo-01",
                cloud_provider="GCP",
                cloud_account_id="lume-ai-agents-prod",
                deployment_environment="development",
                region="us-central1",
                framework="crewai",
                model_provider="google",
                model_name="gemini-2.0-flash",
                description="[DEMO] Multi-agent data analysis system on Cloud Run. Demonstration data only.",
                tools_json=json.dumps(["bigquery_read", "sheets_write", "slack_notify"]),
                mcp_servers_json=json.dumps(["mcp-bigquery-server", "mcp-sheets-server"]),
                registration_source="demo",
                status="ACTIVE",
                connection_status="DISCONNECTED",
                risk_score=28.0,
                open_findings_count=2,
                critical_findings_count=0,
                high_findings_count=0,
            ),
        ]
        db.add_all(agents)
        db.flush()

    # --- Security Findings (demo) ---
    if db.query(SecurityFinding).count() == 0:
        findings = [
            SecurityFinding(
                id="finding-demo-001",
                rule_id="CSPM-PI-001",
                tenant_id="tenant-alpha",
                agent_id="cspm-agent-aws-rag",
                environment_id="env-aws-demo-01",
                resource_id="ecs-task/ai-rag-service",
                title="System prompt vulnerable to direct injection override",
                description="The agent's system prompt can be overridden by crafted user input containing instruction delimiters, potentially exposing internal instructions and bypassing safety controls.",
                category="PROMPT_INJECTION",
                severity="CRITICAL",
                confidence="HIGH",
                cloud_provider="AWS",
                detection_source="demo_seed",
                evidence_json=json.dumps({
                    "test_payload": "Ignore previous instructions...",
                    "response_leaked": True,
                    "demo_data": True,
                }),
                technical_detail="The agent does not implement input sanitization or delimiter-based prompt boundary enforcement. Direct instruction override patterns are not filtered.",
                impact="Attacker could extract system prompt contents, bypass safety guidelines, or manipulate agent behavior to perform unauthorized actions.",
                remediation="Implement multi-layer prompt boundary enforcement. Add input sanitization for instruction override patterns. Deploy the LUME zero-trust gateway prompt scanner.",
                compliance_frameworks_json=json.dumps(["OWASP_TOP_10_LLM_LLM01", "MITRE_ATLAS_AML.T0051"]),
                status="OPEN",
                first_seen_at=now - timedelta(days=3),
                last_seen_at=now - timedelta(hours=6),
            ),
            SecurityFinding(
                id="finding-demo-002",
                rule_id="CSPM-IAM-001",
                tenant_id="tenant-alpha",
                agent_id="cspm-agent-aws-rag",
                environment_id="env-aws-demo-01",
                resource_id="iam-role/AIAgentExecutionRole",
                title="Agent IAM role grants wildcard S3 permissions",
                description="The ECS task role assigned to this agent includes s3:* permissions on all buckets, violating least-privilege principles.",
                category="IAM_PERMISSIONS",
                severity="HIGH",
                confidence="HIGH",
                cloud_provider="AWS",
                detection_source="demo_seed",
                evidence_json=json.dumps({
                    "policy_arn": "arn:aws:iam::123456789012:policy/AIAgentS3Full",
                    "actions": ["s3:*"],
                    "resources": ["*"],
                    "demo_data": True,
                }),
                technical_detail="IAM policy AIAgentS3Full grants Action: s3:* on Resource: *, allowing the agent to read, write, and delete any S3 object in the account.",
                impact="A compromised agent could exfiltrate sensitive data from any S3 bucket or corrupt model training datasets.",
                remediation="Replace wildcard S3 permissions with scoped permissions targeting only required buckets and operations (e.g., s3:GetObject on specific document buckets).",
                compliance_frameworks_json=json.dumps(["CIS_AWS_BENCHMARK_v3.0_1.16", "NIST_800_53_AC_6"]),
                status="OPEN",
                first_seen_at=now - timedelta(days=5),
                last_seen_at=now - timedelta(hours=12),
            ),
            SecurityFinding(
                id="finding-demo-003",
                rule_id="CSPM-DLP-001",
                tenant_id="tenant-alpha",
                agent_id="cspm-agent-aws-rag",
                environment_id="env-aws-demo-01",
                resource_id="ecs-task/ai-rag-service",
                title="Agent responses include unmasked PII from document corpus",
                description="The agent's responses contain customer email addresses and phone numbers from the document knowledge base without DLP redaction.",
                category="DATA_LEAKAGE",
                severity="HIGH",
                confidence="MEDIUM",
                cloud_provider="AWS",
                detection_source="demo_seed",
                evidence_json=json.dumps({
                    "sample_pii_types": ["email", "phone"],
                    "redaction_enabled": False,
                    "demo_data": True,
                }),
                technical_detail="Output responses contain raw PII extracted from indexed documents. No post-processing DLP filter is applied before returning results to users.",
                impact="Sensitive customer PII could be exposed to unauthorized users through the agent's responses.",
                remediation="Enable output DLP redaction using the LUME gateway recursive DLP engine. Configure PII pattern matching for emails, phone numbers, and financial identifiers.",
                compliance_frameworks_json=json.dumps(["OWASP_TOP_10_LLM_LLM06", "NIST_800_53_SI_4"]),
                status="OPEN",
                first_seen_at=now - timedelta(days=2),
                last_seen_at=now - timedelta(hours=4),
            ),
            SecurityFinding(
                id="finding-demo-004",
                rule_id="CSPM-NET-001",
                tenant_id="tenant-alpha",
                agent_id="cspm-agent-aws-rag",
                environment_id="env-aws-demo-01",
                resource_id="security-group/sg-agent-ecs",
                title="Agent container allows unrestricted outbound internet access",
                description="The ECS security group allows egress to 0.0.0.0/0 on all ports, enabling potential data exfiltration or C2 communication.",
                category="NETWORK_SSRF",
                severity="MEDIUM",
                confidence="HIGH",
                cloud_provider="AWS",
                detection_source="demo_seed",
                evidence_json=json.dumps({
                    "sg_rule": {"protocol": "-1", "cidr": "0.0.0.0/0", "direction": "egress"},
                    "demo_data": True,
                }),
                technical_detail="Security group sg-agent-ecs permits all outbound traffic. No egress restrictions or network-level SSRF protections are in place.",
                impact="A compromised agent could exfiltrate data to external servers, access cloud metadata endpoints, or establish reverse shell connections.",
                remediation="Restrict egress to only required destinations. Deploy the LUME SSRF guard for outbound HTTP validation. Apply VPC endpoints for AWS service access.",
                compliance_frameworks_json=json.dumps(["CIS_AWS_BENCHMARK_v3.0_5.3", "NIST_800_53_SC_7"]),
                status="ACKNOWLEDGED",
                first_seen_at=now - timedelta(days=7),
                last_seen_at=now - timedelta(hours=1),
            ),
            SecurityFinding(
                id="finding-demo-005",
                rule_id="CSPM-MCP-001",
                tenant_id="tenant-alpha",
                agent_id="cspm-agent-aws-rag",
                environment_id="env-aws-demo-01",
                resource_id="mcp-document-server",
                title="MCP server tool call permissions not enforced",
                description="The MCP document server does not enforce per-tool authorization policies, allowing any connected agent to invoke all available tools.",
                category="MCP_TOOL_SECURITY",
                severity="MEDIUM",
                confidence="MEDIUM",
                cloud_provider="AWS",
                detection_source="demo_seed",
                evidence_json=json.dumps({
                    "mcp_server": "mcp-document-server",
                    "auth_policy": "none",
                    "demo_data": True,
                }),
                technical_detail="The MCP server accepts tool/call requests without verifying the caller's permitted tool scopes or applying OPA policy evaluation.",
                impact="Any agent with MCP access could invoke privileged tools beyond its intended scope.",
                remediation="Integrate the LUME zero-trust MCP gateway to enforce OPA policies, tenant scoping, and tool-level authorization on all MCP tool calls.",
                compliance_frameworks_json=json.dumps(["OWASP_TOP_10_LLM_LLM06"]),
                status="OPEN",
                first_seen_at=now - timedelta(days=1),
                last_seen_at=now - timedelta(hours=3),
            ),
            SecurityFinding(
                id="finding-demo-006",
                rule_id="CSPM-JB-001",
                tenant_id="tenant-alpha",
                agent_id="cspm-agent-azure-support",
                environment_id="env-azure-demo-01",
                resource_id="container-app/support-bot",
                title="Agent susceptible to persona hijacking jailbreak",
                description="The agent can be manipulated into adopting an unrestricted persona (DAN-style jailbreak) through adversarial prompts.",
                category="JAILBREAK_RESISTANCE",
                severity="HIGH",
                confidence="MEDIUM",
                cloud_provider="AZURE",
                detection_source="demo_seed",
                evidence_json=json.dumps({
                    "jailbreak_type": "DAN_persona",
                    "success_rate": "60%",
                    "demo_data": True,
                }),
                technical_detail="The agent does not implement robust persona persistence or jailbreak detection. DAN-style prompts can override the system persona and bypass safety constraints.",
                impact="Jailbroken agent could generate harmful content, reveal internal configurations, or bypass business logic safeguards.",
                remediation="Implement persona anchoring with reinforcement. Deploy LUME prompt scanner for jailbreak pattern detection. Add runtime behavioral monitoring.",
                compliance_frameworks_json=json.dumps(["OWASP_TOP_10_LLM_LLM01", "MITRE_ATLAS_AML.T0054"]),
                status="OPEN",
                first_seen_at=now - timedelta(days=4),
                last_seen_at=now - timedelta(hours=8),
            ),
            SecurityFinding(
                id="finding-demo-007",
                rule_id="CSPM-LOG-001",
                tenant_id="tenant-alpha",
                agent_id="cspm-agent-azure-support",
                environment_id="env-azure-demo-01",
                resource_id="container-app/support-bot",
                title="Agent interactions not logged to audit trail",
                description="Customer support agent interactions are not being recorded in a tamper-evident audit log.",
                category="LOGGING_AUDIT",
                severity="MEDIUM",
                confidence="HIGH",
                cloud_provider="AZURE",
                detection_source="demo_seed",
                evidence_json=json.dumps({"audit_logging": False, "demo_data": True}),
                technical_detail="The agent does not emit structured audit events for tool invocations or conversation turns. No hash-chain verification is possible for agent actions.",
                impact="Security incidents involving this agent cannot be forensically investigated. Compliance requirements for audit trails are not met.",
                remediation="Integrate with the LUME tamper-evident audit chain. Configure the agent to emit structured security events for all tool calls and significant conversation actions.",
                compliance_frameworks_json=json.dumps(["NIST_800_53_AU_9", "SOC2_CC7.2"]),
                status="OPEN",
                first_seen_at=now - timedelta(days=6),
                last_seen_at=now - timedelta(hours=12),
            ),
            SecurityFinding(
                id="finding-demo-008",
                rule_id="CSPM-CFG-001",
                tenant_id="tenant-alpha",
                agent_id="cspm-agent-azure-support",
                environment_id="env-azure-demo-01",
                resource_id="container-app/support-bot",
                title="Agent configuration stored in unencrypted environment variables",
                description="API keys and model configuration are stored as plain-text environment variables without secrets management.",
                category="AGENT_CONFIG",
                severity="MEDIUM",
                confidence="HIGH",
                cloud_provider="AZURE",
                detection_source="demo_seed",
                evidence_json=json.dumps({"secrets_in_env": True, "key_vault_used": False, "demo_data": True}),
                technical_detail="OPENAI_API_KEY and other sensitive configuration values are set as plain environment variables on the container. Azure Key Vault integration is not configured.",
                impact="Container image inspection or memory dump could expose API keys. Key rotation requires redeployment.",
                remediation="Migrate sensitive configuration to Azure Key Vault with managed identity access. Remove plain-text secrets from container environment.",
                compliance_frameworks_json=json.dumps(["CIS_AZURE_v2.0_8.5"]),
                status="IN_PROGRESS",
                first_seen_at=now - timedelta(days=10),
                last_seen_at=now - timedelta(hours=24),
            ),
            SecurityFinding(
                id="finding-demo-009",
                rule_id="CSPM-ISO-001",
                tenant_id="tenant-alpha",
                agent_id="cspm-agent-gcp-analyst",
                environment_id="env-gcp-demo-01",
                resource_id="cloud-run/data-analyst",
                title="Cross-agent data access not isolated",
                description="Multiple agents in the same project can access each other's BigQuery datasets without tenant boundary enforcement.",
                category="CROSS_TENANT_ISOLATION",
                severity="MEDIUM",
                confidence="MEDIUM",
                cloud_provider="GCP",
                detection_source="demo_seed",
                evidence_json=json.dumps({"shared_dataset": True, "tenant_scoping": False, "demo_data": True}),
                technical_detail="BigQuery datasets used by different agents share the same IAM bindings. No row-level security or dataset-level isolation is enforced between agent workloads.",
                impact="One compromised agent could access or modify data belonging to another agent's tenant scope.",
                remediation="Implement per-tenant BigQuery dataset isolation. Configure row-level security policies. Use separate service accounts per agent with scoped IAM bindings.",
                compliance_frameworks_json=json.dumps(["NIST_800_53_AC_4"]),
                status="OPEN",
                first_seen_at=now - timedelta(days=3),
                last_seen_at=now - timedelta(hours=6),
            ),
            SecurityFinding(
                id="finding-demo-010",
                rule_id="CSPM-DEP-001",
                tenant_id="tenant-alpha",
                agent_id="cspm-agent-gcp-analyst",
                environment_id="env-gcp-demo-01",
                resource_id="cloud-run/data-analyst",
                title="Container base image uses known vulnerable Python packages",
                description="The agent's container image includes Python packages with known CVEs that could be exploited.",
                category="VULNERABLE_DEPENDENCIES",
                severity="LOW",
                confidence="HIGH",
                cloud_provider="GCP",
                detection_source="demo_seed",
                evidence_json=json.dumps({"vulnerable_packages": ["requests==2.28.0", "urllib3==1.26.5"], "demo_data": True}),
                technical_detail="Container image scan detected packages with known vulnerabilities. requests 2.28.0 has CVE-2023-32681 (SSRF via redirect). urllib3 1.26.5 has CVE-2023-43804 (cookie leak).",
                impact="Vulnerable dependencies could be exploited to perform SSRF attacks or leak authentication cookies from the agent's runtime.",
                remediation="Update container base image and pin packages to latest patched versions. Enable automated vulnerability scanning in CI/CD pipeline.",
                compliance_frameworks_json=json.dumps(["OWASP_TOP_10_LLM_LLM05", "NIST_800_53_SI_2"]),
                status="OPEN",
                first_seen_at=now - timedelta(days=14),
                last_seen_at=now - timedelta(hours=48),
            ),
        ]
        db.add_all(findings)
        db.flush()

        # Add finding history entries
        for f in findings:
            db.add(FindingHistory(
                finding_id=f.id,
                previous_status=None,
                new_status=f.status,
                changed_by="system",
                notes="[DEMO] Finding seeded for demonstration purposes",
                timestamp=f.first_seen_at,
            ))

    # --- Scan Jobs (demo) ---
    if db.query(CSPMScanJob).count() == 0:
        scans = [
            CSPMScanJob(
                id="scan-demo-001",
                tenant_id="tenant-alpha",
                target_agent_id="cspm-agent-aws-rag",
                scan_type="AGENT_SECURITY",
                status="COMPLETED",
                started_at=now - timedelta(days=3, hours=2),
                completed_at=now - timedelta(days=3, hours=1, minutes=45),
                total_checks=15,
                passed_checks=10,
                failed_checks=5,
                warning_checks=0,
                findings_count=5,
                severity_distribution_json=json.dumps({"CRITICAL": 1, "HIGH": 2, "MEDIUM": 2, "LOW": 0}),
                coverage_json=json.dumps({"PROMPT_INJECTION": True, "IAM_PERMISSIONS": True, "DATA_LEAKAGE": True, "NETWORK_SSRF": True, "MCP_TOOL_SECURITY": True}),
            ),
            CSPMScanJob(
                id="scan-demo-002",
                tenant_id="tenant-alpha",
                target_agent_id="cspm-agent-azure-support",
                scan_type="AGENT_SECURITY",
                status="COMPLETED",
                started_at=now - timedelta(days=4, hours=1),
                completed_at=now - timedelta(days=4, minutes=50),
                total_checks=12,
                passed_checks=9,
                failed_checks=3,
                warning_checks=0,
                findings_count=3,
                severity_distribution_json=json.dumps({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0}),
                coverage_json=json.dumps({"JAILBREAK_RESISTANCE": True, "LOGGING_AUDIT": True, "AGENT_CONFIG": True}),
            ),
            CSPMScanJob(
                id="scan-demo-003",
                tenant_id="tenant-alpha",
                target_environment_id="env-aws-demo-01",
                scan_type="CLOUD_POSTURE",
                status="COMPLETED",
                started_at=now - timedelta(days=1),
                completed_at=now - timedelta(days=1) + timedelta(minutes=5),
                total_checks=10,
                passed_checks=8,
                failed_checks=2,
                warning_checks=0,
                findings_count=2,
                severity_distribution_json=json.dumps({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0}),
                coverage_json=json.dumps({"IAM_PERMISSIONS": True, "NETWORK_SSRF": True, "CLOUD_CONFIG": True}),
            ),
        ]
        db.add_all(scans)

    # --- CSPM Rules ---
    if db.query(CSPMRule).count() == 0:
        rules = [
            CSPMRule(id="CSPM-PI-001", name="Direct Prompt Injection Detection", category="PROMPT_INJECTION", severity="CRITICAL",
                     description="Detect if an agent's system prompt can be overridden by crafted user input containing instruction delimiters.",
                     detection_logic_status="IMPLEMENTED", framework_mapping_json=json.dumps(["OWASP_TOP_10_LLM_LLM01", "MITRE_ATLAS_AML.T0051"]),
                     last_validation_status="PASS"),
            CSPMRule(id="CSPM-PI-002", name="Indirect Prompt Injection via Context", category="PROMPT_INJECTION", severity="HIGH",
                     description="Detect if external data sources (documents, web content) can inject instructions into agent context.",
                     detection_logic_status="NOT_IMPLEMENTED", framework_mapping_json=json.dumps(["OWASP_TOP_10_LLM_LLM01"])),
            CSPMRule(id="CSPM-JB-001", name="DAN-style Persona Jailbreak", category="JAILBREAK_RESISTANCE", severity="HIGH",
                     description="Test agent resistance to persona hijacking and unrestricted-mode jailbreak attempts.",
                     detection_logic_status="IMPLEMENTED", framework_mapping_json=json.dumps(["OWASP_TOP_10_LLM_LLM01", "MITRE_ATLAS_AML.T0054"]),
                     last_validation_status="PASS"),
            CSPMRule(id="CSPM-IAM-001", name="Agent IAM Least-Privilege Validation", category="IAM_PERMISSIONS", severity="HIGH",
                     description="Verify that agent workload IAM roles do not contain wildcard permissions (Action: *, Resource: *).",
                     detection_logic_status="IMPLEMENTED", framework_mapping_json=json.dumps(["CIS_AWS_BENCHMARK_v3.0_1.16", "NIST_800_53_AC_6"]),
                     last_validation_status="PASS"),
            CSPMRule(id="CSPM-DLP-001", name="Output PII Leakage Detection", category="DATA_LEAKAGE", severity="HIGH",
                     description="Check if agent responses contain unmasked PII (emails, phone numbers, financial identifiers).",
                     detection_logic_status="IMPLEMENTED", framework_mapping_json=json.dumps(["OWASP_TOP_10_LLM_LLM06", "NIST_800_53_SI_4"]),
                     last_validation_status="PASS"),
            CSPMRule(id="CSPM-NET-001", name="Unrestricted Outbound Network Access", category="NETWORK_SSRF", severity="MEDIUM",
                     description="Verify that agent containers have restricted egress rules preventing arbitrary outbound connections.",
                     detection_logic_status="IMPLEMENTED", framework_mapping_json=json.dumps(["CIS_AWS_BENCHMARK_v3.0_5.3", "NIST_800_53_SC_7"]),
                     last_validation_status="PASS"),
            CSPMRule(id="CSPM-MCP-001", name="MCP Tool Call Authorization", category="MCP_TOOL_SECURITY", severity="MEDIUM",
                     description="Verify that MCP servers enforce per-tool authorization policies before executing tool calls.",
                     detection_logic_status="PARTIAL", framework_mapping_json=json.dumps(["OWASP_TOP_10_LLM_LLM06"])),
            CSPMRule(id="CSPM-LOG-001", name="Agent Audit Trail Completeness", category="LOGGING_AUDIT", severity="MEDIUM",
                     description="Verify that all agent interactions are logged to a tamper-evident audit trail.",
                     detection_logic_status="IMPLEMENTED", framework_mapping_json=json.dumps(["NIST_800_53_AU_9", "SOC2_CC7.2"]),
                     last_validation_status="PASS"),
            CSPMRule(id="CSPM-CFG-001", name="Secrets in Environment Variables", category="AGENT_CONFIG", severity="MEDIUM",
                     description="Detect API keys and sensitive tokens stored as plain-text environment variables instead of secrets management services.",
                     detection_logic_status="NOT_IMPLEMENTED", framework_mapping_json=json.dumps(["CIS_AZURE_v2.0_8.5"])),
            CSPMRule(id="CSPM-ISO-001", name="Cross-Tenant Data Isolation", category="CROSS_TENANT_ISOLATION", severity="MEDIUM",
                     description="Verify that agent data access is scoped to the owning tenant and cannot reach other tenants' data.",
                     detection_logic_status="IMPLEMENTED", framework_mapping_json=json.dumps(["NIST_800_53_AC_4"]),
                     last_validation_status="PASS"),
            CSPMRule(id="CSPM-DEP-001", name="Vulnerable Container Dependencies", category="VULNERABLE_DEPENDENCIES", severity="LOW",
                     description="Scan agent container images for known vulnerable packages and outdated base images.",
                     detection_logic_status="NOT_IMPLEMENTED", framework_mapping_json=json.dumps(["OWASP_TOP_10_LLM_LLM05", "NIST_800_53_SI_2"])),
            CSPMRule(id="CSPM-INT-001", name="Insecure External API Integration", category="INSECURE_INTEGRATION", severity="MEDIUM",
                     description="Verify that external API integrations use TLS, authentication, and input validation.",
                     detection_logic_status="NOT_IMPLEMENTED", framework_mapping_json=json.dumps(["NIST_800_53_SC_8"])),
        ]
        db.add_all(rules)
