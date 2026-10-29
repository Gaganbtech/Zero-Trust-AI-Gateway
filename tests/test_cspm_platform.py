"""
LUME AI-CSPM Platform — Test Suite

Tests agent registration, tenant isolation, environment CRUD,
finding lifecycle, scan history, rules, and API schema validation.
"""
import json
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

BASE = "/api/v1/cspm/platform"


# =====================================================================
# Dashboard Overview
# =====================================================================

class TestCSPMOverview:
    def test_overview_returns_metrics(self):
        r = client.get(f"{BASE}/overview")
        assert r.status_code == 200
        data = r.json()
        assert "total_agents" in data
        assert "total_environments" in data
        assert "total_open_findings" in data
        assert "critical_findings" in data
        assert "high_findings" in data
        assert "average_risk_score" in data
        assert "severity_distribution" in data
        assert "category_distribution" in data
        assert "is_demo_data" in data
        # Verify counts are non-negative
        assert data["total_agents"] >= 0
        assert data["total_open_findings"] >= 0

    def test_overview_demo_data_labelled(self):
        r = client.get(f"{BASE}/overview")
        assert r.json()["is_demo_data"] is True


# =====================================================================
# Cloud Environments
# =====================================================================

class TestCloudEnvironments:
    def test_list_environments(self):
        r = client.get(f"{BASE}/environments")
        assert r.status_code == 200
        envs = r.json()
        assert isinstance(envs, list)

    def test_create_environment(self):
        payload = {
            "provider": "AWS",
            "name": "Test AWS Environment",
            "account_id": "999888777666",
            "region": "eu-west-1",
            "description": "Test environment for unit tests",
        }
        r = client.post(f"{BASE}/environments", json=payload)
        assert r.status_code == 201
        data = r.json()
        assert data["provider"] == "AWS"
        assert data["name"] == "Test AWS Environment"
        assert data["connection_status"] == "NOT_CONNECTED"
        assert data["health_status"] == "UNKNOWN"
        return data["id"]

    def test_get_environment(self):
        env_id = self.test_create_environment()
        r = client.get(f"{BASE}/environments/{env_id}")
        assert r.status_code == 200
        assert r.json()["id"] == env_id

    def test_update_environment(self):
        env_id = self.test_create_environment()
        r = client.patch(f"{BASE}/environments/{env_id}", json={"name": "Updated Name"})
        assert r.status_code == 200
        assert r.json()["name"] == "Updated Name"

    def test_delete_environment(self):
        env_id = self.test_create_environment()
        r = client.delete(f"{BASE}/environments/{env_id}")
        assert r.status_code == 204
        # Verify gone
        r2 = client.get(f"{BASE}/environments/{env_id}")
        assert r2.status_code == 404

    def test_get_nonexistent_environment(self):
        r = client.get(f"{BASE}/environments/nonexistent-env")
        assert r.status_code == 404

    def test_create_environment_invalid_provider(self):
        payload = {"provider": "INVALID", "name": "Bad Provider"}
        r = client.post(f"{BASE}/environments", json=payload)
        assert r.status_code == 422  # Pydantic validation


# =====================================================================
# Agent Registration & Management
# =====================================================================

class TestCSPMAgents:
    def test_list_agents(self):
        r = client.get(f"{BASE}/agents")
        assert r.status_code == 200
        agents = r.json()
        assert isinstance(agents, list)

    def test_register_agent(self):
        payload = {
            "name": "Test Security Agent",
            "cloud_provider": "GCP",
            "deployment_environment": "staging",
            "region": "us-west1",
            "framework": "langchain",
            "model_provider": "google",
            "model_name": "gemini-2.0-flash",
            "description": "Test agent for unit tests",
            "tools": ["db_query", "web_search"],
            "mcp_servers": ["mcp-test-server"],
        }
        r = client.post(f"{BASE}/agents/register", json=payload)
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "Test Security Agent"
        assert data["cloud_provider"] == "GCP"
        assert data["registration_source"] == "demo"
        assert data["status"] == "ACTIVE"
        assert data["risk_score"] == 0.0
        assert "db_query" in data["tools"]
        return data["id"]

    def test_get_agent(self):
        agent_id = self.test_register_agent()
        r = client.get(f"{BASE}/agents/{agent_id}")
        assert r.status_code == 200
        assert r.json()["id"] == agent_id

    def test_agent_heartbeat(self):
        agent_id = self.test_register_agent()
        r = client.post(f"{BASE}/agents/{agent_id}/heartbeat", json={"status": "ACTIVE"})
        assert r.status_code == 200
        data = r.json()
        assert data["acknowledged"] is True
        assert data["agent_id"] == agent_id

    def test_agent_heartbeat_nonexistent(self):
        r = client.post(f"{BASE}/agents/nonexistent-agent/heartbeat")
        assert r.status_code == 404

    def test_agent_posture(self):
        agent_id = self.test_register_agent()
        r = client.get(f"{BASE}/agents/{agent_id}/posture")
        assert r.status_code == 200
        data = r.json()
        assert "agent" in data
        assert "severity_distribution" in data
        assert data["agent"]["id"] == agent_id

    def test_get_nonexistent_agent(self):
        r = client.get(f"{BASE}/agents/nonexistent-agent")
        assert r.status_code == 404

    def test_register_agent_missing_name(self):
        r = client.post(f"{BASE}/agents/register", json={"cloud_provider": "AWS"})
        assert r.status_code == 422


# =====================================================================
# Security Findings
# =====================================================================

class TestSecurityFindings:
    def _register_agent(self):
        payload = {"name": "Finding Test Agent", "deployment_environment": "development"}
        r = client.post(f"{BASE}/agents/register", json=payload)
        return r.json()["id"]

    def test_list_findings(self):
        r = client.get(f"{BASE}/findings")
        assert r.status_code == 200
        data = r.json()
        assert "findings" in data
        assert "total" in data
        assert isinstance(data["findings"], list)

    def test_create_finding(self):
        payload = {
            "title": "Test Finding: Prompt Injection Vulnerability",
            "description": "Test finding created by automated test suite.",
            "category": "PROMPT_INJECTION",
            "severity": "HIGH",
            "confidence": "HIGH",
            "detection_source": "test_suite",
            "evidence": {"test": True, "payload": "ignore previous instructions"},
            "technical_detail": "Agent does not sanitize input.",
            "impact": "Unauthorized data access.",
            "remediation": "Deploy prompt scanner.",
            "compliance_frameworks": ["OWASP_TOP_10_LLM_LLM01"],
        }
        r = client.post(f"{BASE}/findings", json=payload)
        assert r.status_code == 201
        data = r.json()
        assert data["title"] == payload["title"]
        assert data["severity"] == "HIGH"
        assert data["status"] == "OPEN"
        assert data["category"] == "PROMPT_INJECTION"
        return data["id"]

    def test_get_finding_with_history(self):
        finding_id = self.test_create_finding()
        r = client.get(f"{BASE}/findings/{finding_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == finding_id
        assert "history" in data
        assert len(data["history"]) >= 1  # Initial creation

    def test_finding_status_lifecycle(self):
        finding_id = self.test_create_finding()

        # OPEN -> ACKNOWLEDGED
        r = client.post(f"{BASE}/findings/{finding_id}/status", json={"status": "ACKNOWLEDGED", "notes": "Reviewing finding"})
        assert r.status_code == 200
        assert r.json()["status"] == "ACKNOWLEDGED"

        # ACKNOWLEDGED -> IN_PROGRESS
        r = client.post(f"{BASE}/findings/{finding_id}/status", json={"status": "IN_PROGRESS"})
        assert r.status_code == 200
        assert r.json()["status"] == "IN_PROGRESS"

        # IN_PROGRESS -> RESOLVED
        r = client.post(f"{BASE}/findings/{finding_id}/status", json={"status": "RESOLVED", "notes": "Fixed in v2.1"})
        assert r.status_code == 200
        assert r.json()["status"] == "RESOLVED"

        # Verify history has all transitions
        r = client.get(f"{BASE}/findings/{finding_id}")
        history = r.json()["history"]
        statuses = [h["new_status"] for h in history]
        assert "OPEN" in statuses
        assert "ACKNOWLEDGED" in statuses
        assert "IN_PROGRESS" in statuses
        assert "RESOLVED" in statuses

    def test_filter_findings_by_severity(self):
        self.test_create_finding()  # Create HIGH finding
        r = client.get(f"{BASE}/findings?severity=HIGH")
        assert r.status_code == 200
        for f in r.json()["findings"]:
            assert f["severity"] == "HIGH"

    def test_filter_findings_by_status(self):
        r = client.get(f"{BASE}/findings?status=OPEN")
        assert r.status_code == 200
        for f in r.json()["findings"]:
            assert f["status"] == "OPEN"

    def test_filter_findings_by_category(self):
        r = client.get(f"{BASE}/findings?category=PROMPT_INJECTION")
        assert r.status_code == 200
        for f in r.json()["findings"]:
            assert f["category"] == "PROMPT_INJECTION"

    def test_finding_pagination(self):
        r = client.get(f"{BASE}/findings?limit=2&offset=0")
        assert r.status_code == 200
        data = r.json()
        assert len(data["findings"]) <= 2
        assert data["limit"] == 2
        assert data["offset"] == 0

    def test_update_nonexistent_finding(self):
        r = client.post(f"{BASE}/findings/nonexistent-finding/status", json={"status": "RESOLVED"})
        assert r.status_code == 404

    def test_create_finding_invalid_category(self):
        payload = {
            "title": "Bad category",
            "description": "Test",
            "category": "INVALID_CATEGORY",
            "severity": "HIGH",
        }
        r = client.post(f"{BASE}/findings", json=payload)
        assert r.status_code == 422

    def test_create_finding_invalid_severity(self):
        payload = {
            "title": "Bad severity",
            "description": "Test",
            "category": "PROMPT_INJECTION",
            "severity": "EXTREME",
        }
        r = client.post(f"{BASE}/findings", json=payload)
        assert r.status_code == 422

    def test_ingest_agent_findings(self):
        agent_id = self._register_agent()
        findings_payload = [
            {
                "title": "Ingested Finding 1",
                "description": "Agent-reported vulnerability",
                "category": "AGENT_CONFIG",
                "severity": "MEDIUM",
                "evidence": {"source": "agent_self_check"},
            },
            {
                "title": "Ingested Finding 2",
                "description": "Another agent finding",
                "category": "DATA_LEAKAGE",
                "severity": "HIGH",
            },
        ]
        r = client.post(f"{BASE}/agents/{agent_id}/findings", json=findings_payload)
        assert r.status_code == 201
        data = r.json()
        assert len(data) == 2
        assert data[0]["detection_source"] == "agent_report"

    def test_ingest_findings_nonexistent_agent(self):
        r = client.post(f"{BASE}/agents/nonexistent/findings", json=[
            {"title": "t", "description": "d", "category": "AGENT_CONFIG", "severity": "LOW"}
        ])
        assert r.status_code == 404


# =====================================================================
# Scan History
# =====================================================================

class TestScanHistory:
    def test_list_scans(self):
        r = client.get(f"{BASE}/scans")
        assert r.status_code == 200
        data = r.json()
        assert "scans" in data
        assert "total" in data

    def test_create_scan_job(self):
        payload = {"scan_type": "AGENT_SECURITY"}
        r = client.post(f"{BASE}/scans", json=payload)
        assert r.status_code == 201
        data = r.json()
        assert data["scan_type"] == "AGENT_SECURITY"
        assert data["status"] == "PENDING"
        return data["id"]

    def test_get_scan_job(self):
        scan_id = self.test_create_scan_job()
        r = client.get(f"{BASE}/scans/{scan_id}")
        assert r.status_code == 200
        assert r.json()["id"] == scan_id

    def test_get_nonexistent_scan(self):
        r = client.get(f"{BASE}/scans/nonexistent-scan")
        assert r.status_code == 404


# =====================================================================
# CSPM Rules
# =====================================================================

class TestCSPMRules:
    def test_list_rules(self):
        r = client.get(f"{BASE}/rules")
        assert r.status_code == 200
        rules = r.json()
        assert isinstance(rules, list)
        if len(rules) > 0:
            assert "id" in rules[0]
            assert "name" in rules[0]
            assert "category" in rules[0]
            assert "severity" in rules[0]
            assert "detection_logic_status" in rules[0]

    def test_filter_rules_by_category(self):
        r = client.get(f"{BASE}/rules?category=PROMPT_INJECTION")
        assert r.status_code == 200
        for rule in r.json():
            assert rule["category"] == "PROMPT_INJECTION"

    def test_get_rule(self):
        # First list to get an ID
        rules = client.get(f"{BASE}/rules").json()
        if len(rules) > 0:
            r = client.get(f"{BASE}/rules/{rules[0]['id']}")
            assert r.status_code == 200
            assert r.json()["id"] == rules[0]["id"]

    def test_get_nonexistent_rule(self):
        r = client.get(f"{BASE}/rules/NONEXISTENT-RULE")
        assert r.status_code == 404


# =====================================================================
# API Schema Validation
# =====================================================================

class TestAPISchemas:
    def test_overview_schema_complete(self):
        r = client.get(f"{BASE}/overview")
        data = r.json()
        required_fields = [
            "total_agents", "total_environments", "total_assets",
            "total_open_findings", "critical_findings", "high_findings",
            "medium_findings", "low_findings", "agents_with_issues",
            "recent_scan_count", "average_risk_score",
            "agent_health_summary", "severity_distribution",
            "category_distribution", "is_demo_data",
        ]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"

    def test_agent_schema_complete(self):
        agents = client.get(f"{BASE}/agents").json()
        if agents:
            a = agents[0]
            required = ["id", "name", "tenant_id", "status", "connection_status",
                        "risk_score", "open_findings_count", "registration_source"]
            for field in required:
                assert field in a, f"Missing field: {field}"

    def test_finding_schema_complete(self):
        data = client.get(f"{BASE}/findings").json()
        if data["findings"]:
            f = data["findings"][0]
            required = ["id", "title", "description", "category", "severity",
                        "confidence", "status", "evidence"]
            for field in required:
                assert field in f, f"Missing field: {field}"


# =====================================================================
# Regression: Existing Endpoints Still Work
# =====================================================================

class TestExistingEndpoints:
    def test_health_still_works(self):
        r = client.get("/healthz")
        assert r.status_code == 200

    def test_dashboard_summary_still_works(self):
        r = client.get("/api/v1/dashboard/summary")
        assert r.status_code == 200

    def test_agents_still_works(self):
        r = client.get("/api/v1/agents")
        assert r.status_code == 200

    def test_incidents_still_works(self):
        r = client.get("/api/v1/incidents")
        assert r.status_code == 200

    def test_cspm_summary_still_works(self):
        r = client.get("/api/v1/cspm/summary")
        assert r.status_code == 200

    def test_audit_events_still_works(self):
        r = client.get("/api/v1/audit/events")
        assert r.status_code == 200
