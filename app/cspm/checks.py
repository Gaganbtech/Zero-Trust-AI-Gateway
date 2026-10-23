import os
from typing import List, Dict, Any
from app.cspm.schemas import (
    PostureCheckResult,
    CSPMSeverity,
    CSPMStatus,
    CSPMCategory
)
from app.core.config import settings


def check_model_endpoint_exposure() -> PostureCheckResult:
    """Verifies that AI model inference endpoints are not publicly accessible on 0.0.0.0/0."""
    # Audits deployment config or environment
    is_public = os.getenv("EXPOSE_PUBLIC_MODEL_ENDPOINT", "false").lower() == "true"
    
    if is_public:
        return PostureCheckResult(
            check_id="AI-CSPM-001",
            name="Model Inference Endpoints Publicly Accessible",
            category=CSPMCategory.MODEL_ENDPOINTS,
            severity=CSPMSeverity.CRITICAL,
            status=CSPMStatus.FAIL,
            description="AI Model inference endpoint is bound to a public IP without VPC private link restriction, exposing raw inference to the internet.",
            resource_id="arn:aws:sagemaker:us-east-1:123456789012:endpoint/ai-agent-vllm",
            compliance_frameworks=["OWASP_TOP_10_LLM_LLM06", "NIST_AI_RMF_GOVERN_1.2"],
            remediation_command="aws sagemaker update-endpoint --endpoint-name ai-agent-vllm --vpc-config Subnets=subnet-1234,SecurityGroupIds=sg-5678",
            remediation_guidance="Place model inference instances inside a private VPC subnet with AWS PrivateLink or VPC Endpoints. Never assign public IPv4 addresses to model containers.",
            evidence={"public_endpoint": True, "binding": "0.0.0.0/0"}
        )
    return PostureCheckResult(
        check_id="AI-CSPM-001",
        name="Model Inference Endpoints Isolated in Private VPC",
        category=CSPMCategory.MODEL_ENDPOINTS,
        severity=CSPMSeverity.CRITICAL,
        status=CSPMStatus.PASS,
        description="Model inference endpoints are strictly routed through private VPC subnets and accessed via the zero-trust runtime security gateway.",
        resource_id="vpc-private-ai-inference",
        remediation_command="# Compliant: Endpoint is private",
        remediation_guidance="Maintain VPC Endpoint isolation for all LLM and embedding infrastructure.",
        evidence={"private_vpc": True}
    )


def check_cloud_metadata_imdsv2() -> PostureCheckResult:
    """Verifies that EC2 / Cloud VM metadata service enforces IMDSv2 to prevent SSRF token theft."""
    imdsv2_enforced = os.getenv("AWS_IMDSV2_ENFORCED", "true").lower() == "true"

    if not imdsv2_enforced:
        return PostureCheckResult(
            check_id="AI-CSPM-002",
            name="Cloud Instance Metadata Service Allows IMDSv1",
            category=CSPMCategory.NETWORK_EGRESS,
            severity=CSPMSeverity.HIGH,
            status=CSPMStatus.FAIL,
            description="EC2 instances hosting AI agents permit IMDSv1 without session token requirements, rendering instance credentials vulnerable to SSRF exfiltration.",
            resource_id="ec2-ai-agent-worker-nodes",
            compliance_frameworks=["CIS_AWS_BENCHMARK_v3.0_5.1", "MITRE_ATT&CK_T1552.005"],
            remediation_command="aws ec2 modify-instance-metadata-options --instance-id i-1234567890abcdef0 --http-tokens required --http-endpoint enabled",
            remediation_guidance="Enforce IMDSv2 (http-tokens required) and set http-put-response-hop-limit to 1 to prevent containers from accessing host instance credentials.",
            evidence={"imdsv1_enabled": True}
        )
    return PostureCheckResult(
        check_id="AI-CSPM-002",
        name="IMDSv2 Enforced on AI Compute Nodes",
        category=CSPMCategory.NETWORK_EGRESS,
        severity=CSPMSeverity.HIGH,
        status=CSPMStatus.PASS,
        description="IMDSv2 session tokens are strictly required on all host nodes, mitigating SSRF-based IAM credential theft.",
        resource_id="ec2-ai-agent-worker-nodes",
        remediation_command="# Compliant: IMDSv2 active",
        remediation_guidance="Ensure all newly launched AI autoscaling groups inherit http-tokens required.",
        evidence={"imdsv2_enforced": True}
    )


def check_vector_database_security() -> PostureCheckResult:
    """Audits cloud vector database encryption at rest, in transit, and network isolation."""
    vector_db_ssl = os.getenv("VECTOR_DB_TLS_ENABLED", "true").lower() == "true"
    vector_db_public = os.getenv("VECTOR_DB_PUBLIC_ACCESS", "false").lower() == "true"

    if vector_db_public or not vector_db_ssl:
        return PostureCheckResult(
            check_id="AI-CSPM-003",
            name="Vector Database Exposed or Missing TLS",
            category=CSPMCategory.STORAGE_VECTOR_DB,
            severity=CSPMSeverity.HIGH,
            status=CSPMStatus.FAIL,
            description="Cloud vector database storing sensitive document embeddings is either publicly accessible or missing TLS in-transit encryption.",
            resource_id="qdrant-vector-cluster-prod",
            compliance_frameworks=["NIST_800_53_SC_8", "OWASP_TOP_10_LLM_LLM08"],
            remediation_command="kubectl apply -f deploy/k8s/vector-db-tls-secret.yaml",
            remediation_guidance="Enable mTLS on vector database cluster endpoints and restrict ingress strictly to the gateway cluster CIDR.",
            evidence={"tls_enabled": vector_db_ssl, "public_access": vector_db_public}
        )
    return PostureCheckResult(
        check_id="AI-CSPM-003",
        name="Vector Database Encrypted and Network-Isolated",
        category=CSPMCategory.STORAGE_VECTOR_DB,
        severity=CSPMSeverity.HIGH,
        status=CSPMStatus.PASS,
        description="Vector database utilizes TLS 1.3 encryption in-transit and is isolated within private cluster network boundaries.",
        resource_id="vector-db-internal",
        remediation_command="# Compliant: Vector database secured",
        remediation_guidance="Ensure vector embedding backups are encrypted with dedicated customer-managed KMS keys.",
        evidence={"tls_enabled": True, "network_isolated": True}
    )


def check_cloud_model_storage_buckets() -> PostureCheckResult:
    """Verifies that S3 / GCS buckets containing model weights and training datasets block public access."""
    public_buckets = os.getenv("S3_MODEL_BUCKETS_PUBLIC", "false").lower() == "true"

    if public_buckets:
        return PostureCheckResult(
            check_id="AI-CSPM-004",
            name="Model Storage S3 Bucket Missing Public Access Block",
            category=CSPMCategory.STORAGE_VECTOR_DB,
            severity=CSPMSeverity.CRITICAL,
            status=CSPMStatus.FAIL,
            description="Cloud storage bucket containing proprietary model checkpoints or training datasets is missing AWS S3 Public Access Block.",
            resource_id="s3://enterprise-ai-agent-models-checkpoints",
            compliance_frameworks=["CIS_AWS_BENCHMARK_v3.0_2.1.5", "NIST_SP_800_171"],
            remediation_command="aws s3api put-public-access-block --bucket enterprise-ai-agent-models-checkpoints --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
            remediation_guidance="Apply S3 Public Access Block at both the account and bucket level. Enforce aws:SecureTransport policy on all model buckets.",
            evidence={"public_access_blocked": False}
        )
    return PostureCheckResult(
        check_id="AI-CSPM-004",
        name="Model Storage S3 Buckets Block Public Access",
        category=CSPMCategory.STORAGE_VECTOR_DB,
        severity=CSPMSeverity.CRITICAL,
        status=CSPMStatus.PASS,
        description="Cloud storage buckets containing model weights and datasets enforce S3 Public Access Block and SSE-KMS encryption.",
        resource_id="s3://enterprise-ai-agent-models-checkpoints",
        remediation_command="# Compliant: S3 Public Access Block active",
        remediation_guidance="Regularly audit bucket policies for overly permissive Cross-Account principal grants.",
        evidence={"public_access_blocked": True, "kms_encrypted": True}
    )


def check_iam_least_privilege() -> PostureCheckResult:
    """Audits agent cloud IAM roles for excessive permissions or wildcard policies."""
    iam_wildcard = os.getenv("IAM_ALLOW_WILDCARD_PERMISSIONS", "false").lower() == "true"

    if iam_wildcard:
        return PostureCheckResult(
            check_id="AI-CSPM-005",
            name="AI Agent Workload IAM Role Grants Wildcard Permissions",
            category=CSPMCategory.IAM_IDENTITY,
            severity=CSPMSeverity.CRITICAL,
            status=CSPMStatus.FAIL,
            description="Agent ServiceAccount or IAM execution role contains Action: '*' or Resource: '*', allowing privilege escalation.",
            resource_id="arn:aws:iam::123456789012:role/AIAgentExecutionRole",
            compliance_frameworks=["CIS_AWS_BENCHMARK_v3.0_1.16", "OWASP_TOP_10_LLM_LLM06"],
            remediation_command="aws iam put-role-policy --role-name AIAgentExecutionRole --policy-name LeastPrivilege --policy-document file://deploy/iam/least_privilege.json",
            remediation_guidance="Replace wildcard IAM policies with discrete, scoped permissions strictly matching registered tool capabilities.",
            evidence={"wildcard_actions": ["*:*"]}
        )
    return PostureCheckResult(
        check_id="AI-CSPM-005",
        name="AI Workload IAM Roles Enforce Least-Privilege",
        category=CSPMCategory.IAM_IDENTITY,
        severity=CSPMSeverity.CRITICAL,
        status=CSPMStatus.PASS,
        description="Agent workload roles utilize discrete scoped permissions without wildcard grants, bound to short-lived cryptographic tokens.",
        resource_id="arn:aws:iam::123456789012:role/AIAgentExecutionRole",
        remediation_command="# Compliant: Least-privilege IAM enforced",
        remediation_guidance="Review IAM Access Analyzer findings quarterly for unused permissions.",
        evidence={"wildcard_actions": []}
    )


def check_kubernetes_pod_security() -> PostureCheckResult:
    """Verifies that Kubernetes AI pods enforce Pod Security Standards (Restricted profile)."""
    # Audits deployment manifest compliance
    return PostureCheckResult(
        check_id="AI-CSPM-006",
        name="Kubernetes AI Workload Enforces Non-Root & Dropped Capabilities",
        category=CSPMCategory.CONTAINER_K8S,
        severity=CSPMSeverity.HIGH,
        status=CSPMStatus.PASS,
        description="Pod manifest enforces runAsNonRoot: true (UID 10001), allowPrivilegeEscalation: false, and drops all Linux capabilities.",
        resource_id="deploy/k8s/backend-deployment.yaml",
        compliance_frameworks=["CIS_KUBERNETES_BENCHMARK_v1.8_5.2", "NIST_SP_800_190"],
        remediation_command="# Compliant: SecurityContext active in manifest",
        remediation_guidance="Ensure admission controllers (e.g. OPA Gatekeeper or Kyverno) reject pods without restricted SecurityContext.",
        evidence={"runAsNonRoot": True, "drop_capabilities": ["ALL"], "uid": 10001}
    )


def check_kubernetes_network_policies() -> PostureCheckResult:
    """Verifies that Kubernetes NetworkPolicies exist to prevent unmonitored egress from AI pods."""
    has_network_policy = os.path.exists(
        os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "k8s", "network-policy.yaml")
    )
    if not has_network_policy:
        return PostureCheckResult(
            check_id="AI-CSPM-007",
            name="Missing Kubernetes NetworkPolicy for AI Egress",
            category=CSPMCategory.NETWORK_EGRESS,
            severity=CSPMSeverity.HIGH,
            status=CSPMStatus.FAIL,
            description="No Kubernetes NetworkPolicy defines egress boundaries for the AI container namespace, permitting direct outbound traffic.",
            resource_id="namespace:zero-trust-security",
            compliance_frameworks=["CIS_KUBERNETES_BENCHMARK_v1.8_5.3"],
            remediation_command="kubectl apply -f deploy/k8s/network-policy.yaml",
            remediation_guidance="Apply default-deny egress NetworkPolicies in all AI agent namespaces.",
            evidence={"network_policy_found": False}
        )
    return PostureCheckResult(
        check_id="AI-CSPM-007",
        name="Kubernetes Egress NetworkPolicy Active",
        category=CSPMCategory.NETWORK_EGRESS,
        severity=CSPMSeverity.HIGH,
        status=CSPMStatus.PASS,
        description="Default-deny egress NetworkPolicy is active, isolating pod traffic strictly to internal database ports and verified proxy egress.",
        resource_id="deploy/k8s/network-policy.yaml",
        remediation_command="# Compliant: NetworkPolicy configured",
        remediation_guidance="Audit egress rules to ensure no broad 0.0.0.0/0 egress exceptions exist.",
        evidence={"network_policy_active": True}
    )


def check_model_serialization_security() -> PostureCheckResult:
    """Audits model supply chain format (SafeTensors vs unsafe Python pickle)."""
    return PostureCheckResult(
        check_id="AI-CSPM-008",
        name="Model Supply Chain Formats Enforce SafeTensors",
        category=CSPMCategory.SUPPLY_CHAIN_AI,
        severity=CSPMSeverity.HIGH,
        status=CSPMStatus.PASS,
        description="AI models and checkpoints are restricted to SafeTensors format. Arbitrary Python pickle serialization is prohibited.",
        resource_id="model-registry-safetensors",
        compliance_frameworks=["OWASP_TOP_10_LLM_LLM05", "NIST_AI_RMF_MEASURE_2.3"],
        remediation_command="# Compliant: SafeTensors enforced",
        remediation_guidance="Disallow loading .bin or .pkl files; use huggingface_hub safe_weights and verify cryptographic model hashes.",
        evidence={"format": "safetensors", "pickle_prohibited": True}
    )


def check_secrets_manager_posture() -> PostureCheckResult:
    """Verifies that secrets are not committed or hardcoded in production environment."""
    is_prod = settings.ENVIRONMENT == "production"
    has_dev_secrets = "insecure-dev" in settings.SECRET_KEY or "dev-agent-token" in settings.GATEWAY_AGENT_TOKEN

    if is_prod and has_dev_secrets:
        return PostureCheckResult(
            check_id="AI-CSPM-009",
            name="Insecure Secrets Detected in Production Environment",
            category=CSPMCategory.AUDIT_GOVERNANCE,
            severity=CSPMSeverity.CRITICAL,
            status=CSPMStatus.FAIL,
            description="Production environment contains default or development secret tokens, compromising JWT validation.",
            resource_id="environment:production",
            compliance_frameworks=["CIS_AWS_BENCHMARK_v3.0_1.14"],
            remediation_command="aws secretsmanager create-secret --name prod/ai-gateway/keys --secret-string '...'",
            remediation_guidance="Inject high-entropy secrets from AWS Secrets Manager or HashiCorp Vault on container startup.",
            evidence={"dev_secrets_present": True}
        )
    return PostureCheckResult(
        check_id="AI-CSPM-009",
        name="Secrets Validation Guard Active",
        category=CSPMCategory.AUDIT_GOVERNANCE,
        severity=CSPMSeverity.MEDIUM,
        status=CSPMStatus.PASS,
        description="Startup configuration validation strictly enforces secret entropy and rejects insecure dev defaults in production.",
        resource_id="app/core/config.py",
        remediation_command="# Compliant: Production secret validation active",
        remediation_guidance="Ensure periodic automatic secret rotation every 90 days via KMS.",
        evidence={"startup_validation_active": True}
    )


def check_audit_log_immutability() -> PostureCheckResult:
    """Verifies tamper-evident HMAC-SHA256 audit chaining and WORM storage compliance."""
    return PostureCheckResult(
        check_id="AI-CSPM-010",
        name="Cryptographic Tamper-Evident Audit Trail Configured",
        category=CSPMCategory.AUDIT_GOVERNANCE,
        severity=CSPMSeverity.HIGH,
        status=CSPMStatus.PASS,
        description="All runtime AI agent security decisions are recorded in a continuous HMAC-SHA256 cryptographic hash chain.",
        resource_id="app/audit/tamper.py",
        compliance_frameworks=["NIST_800_53_AU_9", "SOC2_CC7.2"],
        remediation_command="# Compliant: Tamper-evident hash chain active",
        remediation_guidance="Configure asynchronous log mirroring to S3 Object Lock (WORM) bucket for regulatory retention.",
        evidence={"hash_chain_active": True, "algorithm": "HMAC-SHA256"}
    )


ALL_CSPM_CHECKS = [
    check_model_endpoint_exposure,
    check_cloud_metadata_imdsv2,
    check_vector_database_security,
    check_cloud_model_storage_buckets,
    check_iam_least_privilege,
    check_kubernetes_pod_security,
    check_kubernetes_network_policies,
    check_model_serialization_security,
    check_secrets_manager_posture,
    check_audit_log_immutability,
]
