import os, httpx
from .config import settings

def local_check(d):
    if d.get("agent_id") != "demo-agent": return False, "unknown_agent"
    if d.get("tool") == "db_query":
        ok = (d.get("operation", "").upper() == "SELECT" and d.get("table") == "customers"
              and d.get("destination") == "sqlite://demo" and d.get("method") == "INTERNAL")
        return (True, "policy_allow_read_customers") if ok else (False, "db_policy_denied")
    if d.get("tool") == "weather":
        ok = (d.get("operation", "").upper() == "GET"
              and d.get("destination") == "https://api.weather.example/v1/current"
              and d.get("method") == "GET")
        return (True, "policy_allow_weather_get") if ok else (False, "network_policy_denied")
    return False, "tool_not_allowlisted"

async def authorize(data):
    try:
        async with httpx.AsyncClient(timeout=settings.opa_timeout_seconds) as client:
            response = await client.post(settings.opa_url, json={"input": data})
            response.raise_for_status()
            if response.json().get("result") is True: return True, "opa_allow", "opa"
            return False, "opa_deny", "opa"
    except (httpx.HTTPError, ValueError):
        if os.getenv("OPA_FAIL_CLOSED", "0") == "1":
            return False, "opa_unavailable_fail_closed", "opa"
        allowed, reason = local_check(data)
        return allowed, reason, "local_fallback"
