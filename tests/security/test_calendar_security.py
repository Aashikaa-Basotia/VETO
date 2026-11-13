import pytest
import os
import sqlite3
import json
import uuid
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

# Force test DBs
from gateway.gateway import app
from provenance.verifier import generate_provenance_signature

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_dbs():
    os.environ["VETO_AUDIT_DB"] = "test_calendar_audit.db"
    os.environ["VETO_APPROVAL_DB"] = "test_calendar_approval.db"
    os.environ["VETO_REPLAY_DB"] = "test_calendar_replay.db"
    os.environ["VETO_CALENDAR_ACCESS_TOKEN"] = "mock"
    
    # reset singletons
    import audit.logger
    audit.logger._audit_logger = None
    import approval.engine
    approval.engine._approval_engine = None
    import replay.engine
    replay.engine._replay_engine = None
    
    for db in ["test_calendar_audit.db", "test_calendar_approval.db", "test_calendar_replay.db"]:
        try:
            with sqlite3.connect(db) as conn:
                for table in ["audit_logs", "approval_requests", "replay_state"]:
                    try:
                        conn.execute(f"DELETE FROM {table}")
                    except sqlite3.OperationalError:
                        pass
                conn.commit()
        except sqlite3.OperationalError:
            pass
    yield

def _sign_request(payload: dict) -> dict:
    payload["request_id"] = f"REQ-{uuid.uuid4()}"
    sig = generate_provenance_signature(payload["operation"], payload["arguments"], payload["request_id"])
    payload["provenance_signature"] = sig
    return payload

def test_calendar_legitimate_read():
    """list_calendar_events reaches the mocked Calendar API after security checks."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "list_calendar_events",
        "arguments": {"max_results": 2}
    })
    
    with patch('services.calendar.CalendarAdapter.list_calendar_events', return_value={"items": []}) as mock_list:
        response = client.post("/gateway/execute", json=payload)
        
        assert response.status_code == 200
        assert response.json() == {"items": []}
        mock_list.assert_called_once()

def test_calendar_legitimate_write_requires_approval():
    """create_calendar_event reaches REQUIRE_APPROVAL and does NOT contact Calendar before approval."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "create_calendar_event",
        "arguments": {
            "summary": "Test",
            "start": {"date": "2026-10-10"},
            "end": {"date": "2026-10-11"}
        }
    })
    
    with patch('services.calendar.CalendarAdapter.create_calendar_event') as mock_create:
        response = client.post("/gateway/execute", json=payload)
        
        assert response.status_code == 403
        data = response.json()
        assert data["detail"]["decision"] == "REQUIRE_APPROVAL"
        assert "approval_id" in data["detail"]
        mock_create.assert_not_called()

def test_calendar_approved_write():
    """After valid approval, Calendar API is contacted exactly once."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "create_calendar_event",
        "arguments": {
            "summary": "Test",
            "start": {"date": "2026-10-10"},
            "end": {"date": "2026-10-11"}
        }
    })
    
    response = client.post("/gateway/execute", json=payload)
    approval_id = response.json()["detail"].get("approval_id")
    
    with patch('services.calendar.CalendarAdapter.create_calendar_event', return_value={"id": "new-event"}) as mock_create:
        approve_resp = client.post(f"/approval/{approval_id}/approve")
        assert approve_resp.status_code == 200
        
        # Resubmit
        payload["request_id"] = f"REQ-{uuid.uuid4()}"
        payload["provenance_signature"] = generate_provenance_signature(payload["operation"], payload["arguments"], payload["request_id"])
        exec_resp = client.post("/gateway/execute", json=payload)
        assert exec_resp.status_code == 200
        assert exec_resp.json() == {"id": "new-event"}
        mock_create.assert_called_once()

def test_calendar_replay():
    """Reusing the same request ID is blocked."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "create_calendar_event",
        "arguments": {
            "summary": "Test",
            "start": {"date": "2026-10-10"},
            "end": {"date": "2026-10-11"}
        }
    })
    
    # First time -> REQUIRE_APPROVAL
    r1 = client.post("/gateway/execute", json=payload)
    assert r1.json()["detail"]["decision"] == "REQUIRE_APPROVAL"
    
    approval_id = r1.json()["detail"]["approval_id"]
    client.post(f"/approval/{approval_id}/approve")
    
    # Executing approved request (needs fresh request ID to pass replay the first time)
    payload2 = _sign_request({
        "agent_id": "default_agent",
        "operation": "create_calendar_event",
        "arguments": {
            "summary": "Test",
            "start": {"date": "2026-10-10"},
            "end": {"date": "2026-10-11"}
        }
    })
    
    with patch('services.calendar.CalendarAdapter.create_calendar_event', return_value={"id": "mock"}):
        r2 = client.post("/gateway/execute", json=payload2)
        assert r2.status_code == 200
        
    # Replay it!
    r3 = client.post("/gateway/execute", json=payload2)
    assert r3.status_code == 403
    assert r3.json()["detail"]["decision"] == "BLOCK"
    assert "replay" in r3.json()["detail"]["reason"].lower()

def test_calendar_missing_provenance():
    """Calendar request without signature is blocked."""
    payload = {
        "agent_id": "default_agent",
        "operation": "list_calendar_events",
        "arguments": {"max_results": 2},
        "request_id": f"REQ-{uuid.uuid4()}"
    }
    
    response = client.post("/gateway/execute", json=payload)
    assert response.status_code == 403
    assert response.json()["detail"]["decision"] == "BLOCK"

def test_calendar_tampered_event():
    """Changing event fields after signing is blocked."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "create_calendar_event",
        "arguments": {
            "summary": "Original",
            "start": {"date": "2026-10-10"},
            "end": {"date": "2026-10-11"}
        }
    })
    
    # Tamper
    payload["arguments"]["summary"] = "Hacked!"
    
    response = client.post("/gateway/execute", json=payload)
    assert response.status_code == 403
    assert "provenance_signature" in response.json()["detail"]["reason"]

def test_calendar_unauthorized_capability():
    """Unknown Calendar capability is blocked."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "delete_calendar_event",
        "arguments": {"eventId": "123"}
    })
    
    response = client.post("/gateway/execute", json=payload)
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]["reason"].lower()

def test_calendar_arbitrary_destination():
    """Calendar request attempting to override destination is blocked."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "list_calendar_events",
        "arguments": {"max_results": 2}
    })
    payload["destination_override"] = "http://evil.com"
    
    with patch('services.calendar.CalendarAdapter.list_calendar_events') as mock_list:
        response = client.post("/gateway/execute", json=payload)
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "unknown_destination"
        mock_list.assert_not_called()
    assert response.json()["detail"]["reason"] == "unknown_destination"

def test_calendar_restricted_mode():
    """create_calendar_event is blocked in restricted mode."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "create_calendar_event",
        "arguments": {
            "summary": "Test",
            "start": {"date": "2026-10-10"},
            "end": {"date": "2026-10-11"}
        }
    })
    with patch.dict(os.environ, {"VETO_EXECUTION_MODE": "restricted"}):
        response = client.post("/gateway/execute", json=payload)
    assert response.status_code == 403
    assert "state_changing_operation_blocked_in_restricted_mode" in response.json()["detail"]["reason"]

def test_calendar_missing_credentials():
    """Security checks may ALLOW, but Calendar execution fails safely without contacting API."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "list_calendar_events",
        "arguments": {"max_results": 2}
    })
    
    with patch.dict(os.environ, clear=True):
        response = client.post("/gateway/execute", json=payload)
        assert response.status_code == 500
        assert "Calendar Adapter error" in response.json()["detail"]
        assert "credentials not configured" in response.json()["detail"]

def test_calendar_validation():
    """Malformed or oversized Calendar event arguments must be rejected before network execution."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "create_calendar_event",
        "arguments": {
            "summary": "Test",
            "start": "NOT A DICT",
            "end": {"date": "2026-10-11"}
        }
    })
    
    # Approve it
    r1 = client.post("/gateway/execute", json=payload)
    approval_id = r1.json()["detail"].get("approval_id")
    client.post(f"/approval/{approval_id}/approve")
    
    # Execute it
    payload["request_id"] = f"REQ-{uuid.uuid4()}"
    payload["provenance_signature"] = generate_provenance_signature(payload["operation"], payload["arguments"], payload["request_id"])
    with patch('urllib.request.urlopen') as mock_url:
        r2 = client.post("/gateway/execute", json=payload)
        assert r2.status_code == 500
        assert "Start and end must be dictionaries" in r2.json()["detail"]
        mock_url.assert_not_called()
