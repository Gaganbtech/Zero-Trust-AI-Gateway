from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

REQUEST_COUNT = Counter(
    "ai_gateway_requests_total",
    "Total HTTP requests handled by the gateway",
    ["method", "endpoint", "status_code"]
)

DECISION_COUNT = Counter(
    "ai_gateway_decisions_total",
    "Total runtime zero-trust security decisions",
    ["decision", "tool", "reason"]
)

PROMPT_INJECTION_COUNT = Counter(
    "ai_gateway_prompt_injections_total",
    "Total prompt injection or malicious instructions detected",
    ["category"]
)

DLP_REDACTION_COUNT = Counter(
    "ai_gateway_dlp_redactions_total",
    "Total DLP sensitive findings redacted",
    ["finding_type"]
)

MEDIATION_LATENCY = Histogram(
    "ai_gateway_mediation_duration_seconds",
    "Duration of tool mediation in seconds",
    ["tool", "decision"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)


def get_metrics_payload() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
