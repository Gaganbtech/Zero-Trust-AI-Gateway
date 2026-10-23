import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.session import get_db, SessionLocal, engine, Base
from app.cspm.schemas import CSPMScanSummary, CSPMStatus, CSPMSeverity
from app.cspm.scanner import run_cspm_scan
from app.cspm.service import execute_and_store_scan, get_latest_scan, get_scan_history
from app.cspm.checks import (
    check_model_endpoint_exposure,
    check_cloud_metadata_imdsv2,
    check_vector_database_security,
    check_cloud_model_storage_buckets,
    check_kubernetes_network_policies
)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_cspm_individual_checks():
    """Verify individual CSPM checks return properly structured PostureCheckResults."""
    res_model = check_model_endpoint_exposure()
    assert res_model.check_id == "AI-CSPM-001"
    assert res_model.status in [CSPMStatus.PASS, CSPMStatus.FAIL]
    assert len(res_model.remediation_guidance) > 0
    assert len(res_model.remediation_command) > 0

    res_imds = check_cloud_metadata_imdsv2()
    assert res_imds.check_id == "AI-CSPM-002"
    assert res_imds.severity == CSPMSeverity.HIGH

    res_vector = check_vector_database_security()
    assert res_vector.check_id == "AI-CSPM-003"

    res_storage = check_cloud_model_storage_buckets()
    assert res_storage.check_id == "AI-CSPM-004"

    res_netpol = check_kubernetes_network_policies()
    assert res_netpol.check_id == "AI-CSPM-007"


def test_cspm_scanner_execution():
    """Verify scanner aggregates all checks and calculates category scores and compliance score."""
    summary = run_cspm_scan(cloud_environment="AWS / EKS Test Environment")
    assert isinstance(summary, CSPMScanSummary)
    assert summary.total_checks == 10
    assert summary.passed_checks + summary.failed_checks + summary.warning_checks == 10
    assert 0.0 <= summary.compliance_score <= 100.0
    assert "MODEL_ENDPOINTS" in summary.category_scores
    assert "CONTAINER_K8S" in summary.category_scores
    assert len(summary.findings) == 10


def test_cspm_service_persistence(db_session):
    """Verify scans are saved to database and retrieved correctly."""
    scan_summary = execute_and_store_scan(db_session, cloud_environment="Staging Cloud AI")
    assert scan_summary.cloud_environment == "Staging Cloud AI"

    latest = get_latest_scan(db_session)
    assert latest.scan_id == scan_summary.scan_id
    assert latest.compliance_score == scan_summary.compliance_score

    history = get_scan_history(db_session, limit=5)
    assert len(history) >= 1
    assert any(h["scan_id"] == scan_summary.scan_id for h in history)


def test_cspm_api_summary(client):
    """Test GET /api/v1/cspm/summary."""
    response = client.get("/api/v1/cspm/summary")
    assert response.status_code == 200
    data = response.json()
    assert "compliance_score" in data
    assert "total_checks" in data
    assert "category_scores" in data
    assert "findings" in data
    assert data["total_checks"] == 10


def test_cspm_api_trigger_scan(client):
    """Test POST /api/v1/cspm/scan."""
    response = client.post(
        "/api/v1/cspm/scan",
        json={"cloud_environment": "GCP Vertex AI & GKE Cluster"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["cloud_environment"] == "GCP Vertex AI & GKE Cluster"
    assert data["total_checks"] == 10
    assert len(data["findings"]) == 10


def test_cspm_api_findings_filtering(client):
    """Test GET /api/v1/cspm/findings with filters."""
    # All findings
    resp_all = client.get("/api/v1/cspm/findings")
    assert resp_all.status_code == 200
    all_findings = resp_all.json()
    assert len(all_findings) == 10

    # Filter by status PASS
    resp_pass = client.get("/api/v1/cspm/findings?status=PASS")
    assert resp_pass.status_code == 200
    pass_findings = resp_pass.json()
    assert all(f["status"] == "PASS" for f in pass_findings)


def test_cspm_api_history(client):
    """Test GET /api/v1/cspm/history."""
    resp = client.get("/api/v1/cspm/history?limit=10")
    assert resp.status_code == 200
    history = resp.json()
    assert isinstance(history, list)
    assert len(history) >= 1
