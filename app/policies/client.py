import logging
from typing import Dict, Any, Tuple
import httpx
from app.core.config import settings

logger = logging.getLogger(__name__)


def local_policy_fallback(data: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Development-only fallback policy evaluation.
    Enforces identical zero-trust rules locally when OPA is not running in dev mode.
    """
    agent_id = data.get("agent_id")
    if agent_id not in {"demo-agent", "agent-analytics-01", "agent-beta-support"}:
        return False, "unknown_agent"

    tool = data.get("tool")
    operation = (data.get("operation") or "").upper()
    destination = data.get("destination", "")
    method = (data.get("method") or "").upper()
    scopes = data.get("scopes", [])
    args = data.get("args") or {}

    # Check human approval requirement
    if data.get("risk_level") == "CRITICAL" or operation in {"EXPORT_ALL", "MASS_DELETE", "ADMIN_RESET"}:
        return False, "requires_human_approval"

    # Tool: db_query
    if tool == "db_query":
        if operation in {"DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "TRUNCATE"}:
            return False, "destructive_sql_prohibited"
        if operation != "SELECT":
            return False, "db_policy_denied_operation"
        if data.get("table") != "customers":
            return False, "db_policy_denied_table"
        if destination not in {"sqlite://demo", "internal://database", "postgresql://internal"}:
            return False, "unapproved_destination"
        if method != "INTERNAL":
            return False, "db_policy_denied_method"
        if "customer:read" not in scopes and "*" not in scopes:
            return False, "missing_required_scope"

        # Check column allowlist
        allowed_cols = {"id", "name", "email", "phone", "card_number", "account_balance"}
        requested_cols = args.get("columns", ["id", "name", "email"])
        if not isinstance(requested_cols, list) or not requested_cols:
            return False, "disallowed_db_columns"
        if any(col not in allowed_cols for col in requested_cols):
            return False, "disallowed_db_columns"

        # Check row limits
        limit = args.get("limit", 10)
        if not isinstance(limit, int) or isinstance(limit, bool) or not (1 <= limit <= 20):
            return False, "db_row_limit_exceeded"

        return True, "policy_allow_read_customers"

    # Tool: weather
    if tool == "weather":
        if operation != "GET" or method != "GET":
            return False, "network_policy_denied_method"
        if destination != "https://api.weather.example/v1/current":
            return False, "unapproved_destination"
        if "weather:read" not in scopes and "*" not in scopes:
            return False, "missing_required_scope"
        return True, "policy_allow_weather_get"

    # Tool: safe_http
    if tool == "safe_http":
        if method not in {"GET", "POST"}:
            return False, "network_policy_denied_method"
        if not any(destination.startswith(prefix) for prefix in [
            "https://api.weather.example/",
            "https://api.github.com/",
            "https://httpbin.org/"
        ]):
            return False, "unapproved_destination"
        if "http:egress" not in scopes and "*" not in scopes:
            return False, "missing_required_scope"
        return True, "policy_allow_safe_http"

    return False, "tool_not_allowlisted"


async def evaluate_policy(data: Dict[str, Any]) -> Tuple[bool, str, str]:
    """
    Evaluates runtime security policy for a requested tool action.
    Returns: (is_allowed: bool, reason_code: str, policy_source: str)
    Fails closed when OPA is unavailable in production.
    """
    try:
        async with httpx.AsyncClient(timeout=settings.OPA_TIMEOUT_SECONDS) as client:
            response = await client.post(settings.OPA_URL, json={"input": data})
            response.raise_for_status()
            res_json = response.json()
            result = res_json.get("result")

            # Handle both boolean results and structured dict results
            if isinstance(result, bool):
                if result is True:
                    return True, "opa_allow", "opa"
                return False, "opa_deny", "opa"
            elif isinstance(result, dict):
                allowed = result.get("allow", False)
                reason = result.get("reason", "opa_allow" if allowed else "opa_deny")
                if result.get("requires_human_approval", False):
                    return False, "requires_human_approval", "opa"
                return bool(allowed), str(reason), "opa"
            else:
                # Unexpected response schema -> fail closed
                logger.error("OPA returned malformed result schema: %s", res_json)
                return False, "opa_malformed_response_fail_closed", "opa"

    except Exception as exc:
        logger.warning("OPA request failed (%s): %s", type(exc).__name__, exc)
        if settings.OPA_FAIL_CLOSED or settings.ENVIRONMENT == "production":
            return False, "opa_unavailable_fail_closed", "opa"

        # Development local fallback
        allowed, reason = local_policy_fallback(data)
        return allowed, reason, "local_fallback"
