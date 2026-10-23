from .registry import registry, ToolDefinition, ToolRegistry
from .db_tool import execute_customer_query
from .weather_tool import execute_weather_tool
from .http_tool import execute_safe_http_tool


# Register Default Tools
registry.register(
    ToolDefinition(
        name="db_query",
        description="Parameterized, tenant-scoped query on customer database records.",
        allowed_operations=["SELECT"],
        permitted_resources=["customers"],
        required_workload_scopes=["customer:read"],
        destination_restrictions=["sqlite://demo", "internal://database", "postgresql://internal"],
        data_classification="CONFIDENTIAL",
        risk_classification="MEDIUM",
        execution_timeout_seconds=5.0,
    ),
    execute_customer_query
)

registry.register(
    ToolDefinition(
        name="weather",
        description="Current meteorological observations from verified weather endpoint.",
        allowed_operations=["GET"],
        permitted_resources=["weather_data"],
        required_workload_scopes=["weather:read"],
        destination_restrictions=["https://api.weather.example/v1/current"],
        data_classification="PUBLIC",
        risk_classification="LOW",
        execution_timeout_seconds=3.0,
    ),
    execute_weather_tool
)

registry.register(
    ToolDefinition(
        name="safe_http",
        description="SSRF-protected outbound HTTP client restricted to approved hostnames.",
        allowed_operations=["GET", "POST"],
        permitted_resources=["external_api"],
        required_workload_scopes=["http:egress"],
        destination_restrictions=["https://api.weather.example/", "https://api.github.com/", "https://httpbin.org/"],
        data_classification="INTERNAL",
        risk_classification="MEDIUM",
        execution_timeout_seconds=5.0,
    ),
    execute_safe_http_tool
)


__all__ = [
    "registry",
    "ToolDefinition",
    "ToolRegistry",
    "execute_customer_query",
    "execute_weather_tool",
    "execute_safe_http_tool",
]
