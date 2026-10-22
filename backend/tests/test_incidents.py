from fastapi.testclient import TestClient
from app.main import app
from app.core.errors import PlaybookNotFoundError

client = TestClient(app)


def test_triage_valid_incident_returns_200():
    """
    Ensure a well-formed incident triage request returns HTTP 200 and matches response schema.
    """
    payload = {
        "title": "SSH Brute Force from Unknown External IP",
        "description": "Repeated unauthorized authentication attempts detected on bastion-01 auth logs.",
        "raw_logs": "Oct 22 10:14:02 bastion-01 sshd[2841]: Failed password for invalid user admin from 198.51.100.44 port 48210 ssh2\nOct 22 10:14:04 bastion-01 sshd[2842]: Failed password for invalid user root from 198.51.100.44 port 48211 ssh2",
        "source_ip": "198.51.100.44",
        "affected_asset": "bastion-01",
    }
    response = client.post("/api/v1/incidents/triage", json=payload)
    assert response.status_code == 200
    
    data = response.json()
    assert "incident_id" in data
    assert data["suggested_severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert data["incident_category"] in ["BRUTE_FORCE", "PHISHING", "MALWARE", "UNAUTHORIZED_ACCESS", "PRIVILEGE_ESCALATION", "DATA_EXFILTRATION", "OTHER"]
    assert isinstance(data["supporting_evidence"], list)
    assert isinstance(data["recommended_steps"], list)
    assert isinstance(data["source_references"], list)
    assert len(data["source_references"]) > 0
    assert "X-Request-ID" in response.headers


def test_triage_validation_failure_on_missing_logs():
    """
    Ensure missing or overly short raw_logs triggers HTTP 422 with structured field error.
    """
    invalid_payload = {
        "title": "Valid Alert Title",
        "description": "Valid description of the security incident context.",
        "raw_logs": "short",  # min length is 10
    }
    response = client.post("/api/v1/incidents/triage", json=invalid_payload)
    assert response.status_code == 422

    data = response.json()
    assert data["error"] == "VALIDATION_ERROR"
    assert "errors" in data
    assert any(err["field"] == "raw_logs" for err in data["errors"])
    assert "request_id" in data


def test_triage_validation_failure_on_short_title():
    """
    Ensure title shorter than 3 characters triggers 422.
    """
    invalid_payload = {
        "title": "ab",
        "description": "Valid description with sufficient characters.",
        "raw_logs": "Sample log text exceeding ten chars requirement.",
    }
    response = client.post("/api/v1/incidents/triage", json=invalid_payload)
    assert response.status_code == 422

    data = response.json()
    assert data["error"] == "VALIDATION_ERROR"
    assert any(err["field"] == "title" for err in data["errors"])


def test_domain_exception_handling():
    """
    Ensure custom domain exceptions caught by centralized error handler return standardized JSON.
    """
    from fastapi import APIRouter
    test_router = APIRouter()

    @test_router.get("/api/v1/test-error")
    def trigger_error():
        raise PlaybookNotFoundError("Test playbook PB-999 is missing")

    app.include_router(test_router)

    response = client.get("/api/v1/test-error")
    assert response.status_code == 404
    data = response.json()
    assert data["error"] == "PLAYBOOK_NOT_FOUND"
    assert data["detail"] == "Test playbook PB-999 is missing"
    assert "request_id" in data
