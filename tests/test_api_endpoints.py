import pytest


def test_health_probes(client):
    r_live = client.get("/health/live")
    assert r_live.status_code == 200
    assert r_live.json()["status"] == "alive"

    r_ready = client.get("/health/ready")
    assert r_ready.status_code == 200
    assert r_ready.json()["database"] == "connected"


def test_agent_inventory_endpoint(client):
    r = client.get("/api/v1/agents")
    assert r.status_code == 200
    agents = r.json()
    assert len(agents) >= 2
    agent_ids = [a["id"] for a in agents]
    assert "demo-agent" in agent_ids
    assert "agent-analytics-01" in agent_ids


def test_dashboard_summary_endpoint(client):
    r = client.get("/api/v1/dashboard/summary")
    assert r.status_code == 200
    data = r.json()
    assert "total_events" in data
    assert "allowed_actions" in data
    assert "blocked_actions" in data
    assert "active_incidents" in data


def test_incidents_endpoint(client):
    r = client.get("/api/v1/incidents")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_policies_endpoint(client):
    r = client.get("/api/v1/policies")
    assert r.status_code == 200
    policies = r.json()
    assert len(policies) >= 1
    assert "checksum" in policies[0]


def test_prometheus_metrics_endpoint(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "ai_gateway_requests_total" in r.text
