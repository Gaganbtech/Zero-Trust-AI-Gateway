import re
from typing import Dict, Any


async def execute_weather_tool(args: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Controlled weather tool execution.
    Validates city parameter and returns weather data.
    """
    raw_city = str(args.get("city", "Bengaluru")).strip()
    # Strip any dangerous or non-alphanumeric characters
    city = re.sub(r"[^a-zA-Z0-9\s\.\-]", "", raw_city)[:80] or "Bengaluru"

    return {
        "city": city,
        "temperature_c": 28,
        "temperature_f": 82.4,
        "condition": "Partly Cloudy",
        "humidity_percent": 65,
        "source": "https://api.weather.example/v1/current",
        "verified_agent": getattr(context, "agent_id", "demo-agent")
    }
