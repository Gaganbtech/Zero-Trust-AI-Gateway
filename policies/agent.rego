package ai_gateway

import rego.v1

# Zero-Trust Default Deny
default allow := false
default reason := "default_deny_no_rule_matched"
default requires_human_approval := false

allowed_agents := {
    "demo-agent",
    "agent-analytics-01",
    "agent-beta-support",
    "agent-aws-workload-01",
    "agent-azure-workload-01",
    "agent-gcp-workload-01",
    "agent-gcp-bi"
}

# Approved columns for db_query
allowed_db_columns := {"id", "name", "email", "phone", "card_number", "account_balance"}


# Allow rule 1: Read customer records for authorized agent within same tenant
allow if {
    input.agent_id in allowed_agents
    input.tool == "db_query"
    upper(input.operation) == "SELECT"
    input.table == "customers"
    valid_db_destination
    input.method == "INTERNAL"
    input_has_scope("customer:read")
    valid_columns
    valid_limit
}

reason := "policy_allow_read_customers" if {
    input.tool == "db_query"
    upper(input.operation) == "SELECT"
    input.table == "customers"
    valid_db_destination
    input.method == "INTERNAL"
    input_has_scope("customer:read")
    valid_columns
    valid_limit
}

# Allow rule 2: Weather information service
allow if {
    input.agent_id in allowed_agents
    input.tool == "weather"
    upper(input.operation) == "GET"
    input.method == "GET"
    input.destination == "https://api.weather.example/v1/current"
    input_has_scope("weather:read")
}

reason := "policy_allow_weather_get" if {
    input.agent_id in allowed_agents
    input.tool == "weather"
    upper(input.operation) == "GET"
    input.method == "GET"
    input.destination == "https://api.weather.example/v1/current"
    input_has_scope("weather:read")
}

# Allow rule 3: Safe outbound HTTP egress
allow if {
    input.agent_id in allowed_agents
    input.tool == "safe_http"
    valid_http_method
    valid_outbound_destination
    input_has_scope("http:egress")
}

reason := "policy_allow_safe_http" if {
    input.agent_id in allowed_agents
    input.tool == "safe_http"
    valid_http_method
    valid_outbound_destination
    input_has_scope("http:egress")
}

reason := "unknown_agent" if {
    not input.agent_id in allowed_agents
}

# Specific denial reasons
reason := "destructive_sql_prohibited" if {
    input.tool == "db_query"
    upper(input.operation) in {"DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "TRUNCATE"}
}

reason := "disallowed_db_columns" if {
    input.tool == "db_query"
    not valid_columns
}

reason := "db_row_limit_exceeded" if {
    input.tool == "db_query"
    not valid_limit
}

reason := "unapproved_destination" if {
    not valid_outbound_destination
    not valid_db_destination
}

reason := "missing_required_scope" if {
    input.tool == "db_query"
    not input_has_scope("customer:read")
}

# Human Approval Detection
requires_human_approval if {
    input.risk_level == "CRITICAL"
}

requires_human_approval if {
    input.operation in {"EXPORT_ALL", "MASS_DELETE", "ADMIN_RESET"}
}

# Helpers
valid_db_destination if {
    input.destination in {"sqlite://demo", "internal://database", "postgresql://internal", "postgresql://internal-db"}
}

valid_http_method if {
    upper(input.method) in {"GET", "POST"}
}

valid_outbound_destination if {
    startswith(input.destination, "https://api.weather.example/")
}

valid_outbound_destination if {
    startswith(input.destination, "https://api.github.com/")
}

valid_outbound_destination if {
    startswith(input.destination, "https://httpbin.org/")
}

input_has_scope(required_scope) if {
    required_scope in input.scopes
}

input_has_scope(required_scope) if {
    "*" in input.scopes
}

valid_columns if {
    not input.args.columns
}

valid_columns if {
    is_array(input.args.columns)
    count(input.args.columns) > 0
    every col in input.args.columns {
        col in allowed_db_columns
    }
}

valid_limit if {
    not input.args.limit
}

valid_limit if {
    is_number(input.args.limit)
    input.args.limit > 0
    input.args.limit <= 20
}
