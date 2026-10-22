from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check_returns_200_and_valid_schema():
    """
    Ensure the health endpoint returns HTTP 200, status 'ok', and expected application fields.
    """
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "CyberSage AI"
    assert data["version"] == "0.1.0"
    assert "timestamp" in data
