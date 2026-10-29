import json
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.init_db import init_database

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    init_database()

client = TestClient(app)


def test_mcp_initialize():
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }
    resp = client.post("/api/v1/mcp", json=req)
    assert resp.status_code == 200
    data = resp.json()
    assert data["jsonrpc"] == "2.0"
    assert "result" in data
    assert data["result"]["serverInfo"]["name"] == "zero-trust-ai-gateway-mcp"
    assert "tools" in data["result"]["capabilities"]


def test_mcp_tools_list():
    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }
    resp = client.post("/api/v1/mcp", json=req)
    assert resp.status_code == 200
    data = resp.json()
    assert "result" in data
    tools = data["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "db_query" in tool_names
    assert "safe_http" in tool_names
    assert "weather" in tool_names
    assert "cspm_scan" in tool_names


def test_mcp_tool_call_db_query_success():
    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "db_query",
            "arguments": {
                "table": "customers",
                "columns": ["id", "name", "email"],
                "limit": 3
            },
            "agent_id": "demo-agent",
            "tenant_id": "tenant-alpha"
        }
    }
    resp = client.post("/api/v1/mcp", json=req)
    assert resp.status_code == 200
    data = resp.json()
    assert data["result"]["isError"] is False
    assert data["result"]["_zero_trust"]["decision"] == "ALLOW"


def test_mcp_tool_call_ssrf_blocked():
    req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "safe_http",
            "arguments": {
                "url": "http://169.254.169.254/latest/meta-data/"
            },
            "agent_id": "demo-agent"
        }
    }
    resp = client.post("/api/v1/mcp", json=req)
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("error") is not None
    assert data["error"]["code"] == -32000


def test_mcp_operator_test_endpoint():
    payload = {
        "tool_name": "weather",
        "arguments": {"city": "Bengaluru"},
        "agent_id": "demo-agent",
        "tenant_id": "tenant-alpha"
    }
    resp = client.post("/api/v1/mcp/test-call", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["result"]["isError"] is False
