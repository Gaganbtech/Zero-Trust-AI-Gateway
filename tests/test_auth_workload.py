import pytest
from datetime import timedelta
from fastapi.testclient import TestClient
from app.main import app
from app.auth.security import create_workload_token, verify_workload_token, hash_password
from app.database.session import SessionLocal
from app.database.models import User, AgentRegistryItem


def test_workload_token_generation_and_verification():
    token = create_workload_token(
        agent_id="test-agent-01",
        tenant_id="tenant-alpha",
        scopes=["customer:read"],
        allowed_tools=["db_query"]
    )
    claims = verify_workload_token(token)
    assert claims["sub"] == "test-agent-01"
    assert claims["tenant_id"] == "tenant-alpha"
    assert "customer:read" in claims["scopes"]


def test_workload_token_expired_rejected():
    token = create_workload_token(
        agent_id="test-agent-01",
        tenant_id="tenant-alpha",
        scopes=["customer:read"],
        allowed_tools=["db_query"],
        expires_delta=timedelta(seconds=-1)
    )
    with pytest.raises(Exception):
        verify_workload_token(token)


def test_workload_token_forged_rejected(client):
    forged_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciIsImF1ZCI6Inplcm8tdHJ1c3QtZ2F0ZXdheS1hcGkiLCJpc3MiOiJ6ZXJvLXRydXN0LWdhdGV3YXktYXV0aC1hdXRob3JpdHkiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtYWxwaGEiLCJzY29wZXMiOlsiKiJdfQ.invalidsignature123"
    r = client.post(
        "/api/v1/agents/demo-agent/actions",
        headers={"Authorization": f"Bearer {forged_token}"},
        json={
            "agent_id": "demo-agent",
            "tool": "db_query",
            "operation": "SELECT",
            "destination": "internal://database",
            "method": "INTERNAL",
            "args": {"columns": ["name"]}
        }
    )
    assert r.status_code == 401


def test_agent_impersonation_blocked(client):
    # Token issued for agent-analytics-01
    token = create_workload_token(
        agent_id="agent-analytics-01",
        tenant_id="tenant-alpha",
        scopes=["customer:read"],
        allowed_tools=["db_query"]
    )
    # Attacker calls endpoint with URL claiming demo-agent
    r = client.post(
        "/api/v1/agents/demo-agent/actions",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "agent_id": "demo-agent",
            "tool": "db_query",
            "operation": "SELECT",
            "destination": "internal://database",
            "method": "INTERNAL",
            "args": {"columns": ["name"]}
        }
    )
    assert r.status_code == 403


def test_human_operator_login_and_rbac(client):
    # 1. Login with correct admin credentials
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "AdminSecure2026!"}
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    assert token is not None

    # 2. Check profile
    me_res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "admin"

    # 3. Viewer has restricted role
    viewer_res = client.post(
        "/api/v1/auth/login",
        json={"username": "viewer", "password": "ViewerSecure2026!"}
    )
    assert viewer_res.status_code == 200
    viewer_token = viewer_res.json()["access_token"]

    # 4. Viewer cannot issue workload tokens (requires admin/analyst)
    issue_res = client.post(
        "/api/v1/auth/token",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"agent_id": "demo-agent", "tenant_id": "tenant-alpha"}
    )
    assert issue_res.status_code == 403
