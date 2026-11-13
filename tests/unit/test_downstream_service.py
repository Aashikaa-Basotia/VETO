from fastapi.testclient import TestClient
from mcp_servers.downstream_service import app

client = TestClient(app)

def test_get_status():
    response = client.get("/status")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "VETO controlled downstream service"
    }

def test_create_record_success():
    response = client.post("/records", json={"name": "test-name", "value": "test-value"})
    assert response.status_code == 200
    assert response.json() == {
        "created": True,
        "record_id": "REC-001",
        "name": "test-name",
        "value": "test-value"
    }

def test_create_record_missing_field():
    response = client.post("/records", json={"name": "test-name"})
    assert response.status_code == 422 # FastAPI validation

def test_create_record_empty_fields():
    response = client.post("/records", json={"name": "", "value": ""})
    assert response.status_code == 400
