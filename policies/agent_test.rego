package ai_gateway_test

import rego.v1
import data.ai_gateway

# Test 1: Allow valid customer query
test_allow_valid_customer_query if {
    mock_input := {
        "agent_id": "demo-agent",
        "tenant_id": "tenant-alpha",
        "tool": "db_query",
        "operation": "SELECT",
        "table": "customers",
        "destination": "internal://database",
        "method": "INTERNAL",
        "scopes": ["customer:read"],
        "args": {
            "columns": ["id", "name", "email"],
            "limit": 10
        }
    }
    ai_gateway.allow with input as mock_input
    ai_gateway.reason == "policy_allow_read_customers" with input as mock_input
}

# Test 2: Deny destructive DROP statement
test_deny_destructive_drop if {
    mock_input := {
        "agent_id": "demo-agent",
        "tenant_id": "tenant-alpha",
        "tool": "db_query",
        "operation": "DROP",
        "table": "customers",
        "destination": "internal://database",
        "method": "INTERNAL",
        "scopes": ["customer:read"],
        "args": {}
    }
    not ai_gateway.allow with input as mock_input
    ai_gateway.reason == "destructive_sql_prohibited" with input as mock_input
}

# Test 3: Deny DELETE statement
test_deny_destructive_delete if {
    mock_input := {
        "agent_id": "demo-agent",
        "tenant_id": "tenant-alpha",
        "tool": "db_query",
        "operation": "DELETE",
        "table": "customers",
        "destination": "internal://database",
        "method": "INTERNAL",
        "scopes": ["customer:read"],
        "args": {}
    }
    not ai_gateway.allow with input as mock_input
    ai_gateway.reason == "destructive_sql_prohibited" with input as mock_input
}

# Test 4: Deny disallowed database column
test_deny_disallowed_columns if {
    mock_input := {
        "agent_id": "demo-agent",
        "tenant_id": "tenant-alpha",
        "tool": "db_query",
        "operation": "SELECT",
        "table": "customers",
        "destination": "internal://database",
        "method": "INTERNAL",
        "scopes": ["customer:read"],
        "args": {
            "columns": ["id", "system_passwords_dump"]
        }
    }
    not ai_gateway.allow with input as mock_input
    ai_gateway.reason == "disallowed_db_columns" with input as mock_input
}

# Test 5: Deny excessive row limit (> 20)
test_deny_excessive_limit if {
    mock_input := {
        "agent_id": "demo-agent",
        "tenant_id": "tenant-alpha",
        "tool": "db_query",
        "operation": "SELECT",
        "table": "customers",
        "destination": "internal://database",
        "method": "INTERNAL",
        "scopes": ["customer:read"],
        "args": {
            "columns": ["name"],
            "limit": 1000
        }
    }
    not ai_gateway.allow with input as mock_input
    ai_gateway.reason == "db_row_limit_exceeded" with input as mock_input
}

# Test 6: Deny query when agent lacks required scope
test_deny_missing_scope if {
    mock_input := {
        "agent_id": "demo-agent",
        "tenant_id": "tenant-alpha",
        "tool": "db_query",
        "operation": "SELECT",
        "table": "customers",
        "destination": "internal://database",
        "method": "INTERNAL",
        "scopes": ["irrelevant:scope"],
        "args": {}
    }
    not ai_gateway.allow with input as mock_input
    ai_gateway.reason == "missing_required_scope" with input as mock_input
}

# Test 7: Allow approved weather call
test_allow_weather_service if {
    mock_input := {
        "agent_id": "demo-agent",
        "tenant_id": "tenant-alpha",
        "tool": "weather",
        "operation": "GET",
        "method": "GET",
        "destination": "https://api.weather.example/v1/current",
        "scopes": ["weather:read"]
    }
    ai_gateway.allow with input as mock_input
    ai_gateway.reason == "policy_allow_weather_get" with input as mock_input
}

# Test 8: Deny unapproved egress destination
test_deny_unapproved_egress if {
    mock_input := {
        "agent_id": "demo-agent",
        "tenant_id": "tenant-alpha",
        "tool": "weather",
        "operation": "GET",
        "method": "GET",
        "destination": "https://malicious-exfiltration.attacker.com/steal",
        "scopes": ["weather:read"]
    }
    not ai_gateway.allow with input as mock_input
}

# Test 9: Human approval requirement for CRITICAL actions
test_human_approval_required if {
    mock_input := {
        "agent_id": "demo-agent",
        "tenant_id": "tenant-alpha",
        "tool": "db_query",
        "operation": "EXPORT_ALL",
        "risk_level": "CRITICAL",
        "scopes": ["*"],
        "destination": "internal://database",
        "method": "INTERNAL"
    }
    ai_gateway.requires_human_approval with input as mock_input
}
