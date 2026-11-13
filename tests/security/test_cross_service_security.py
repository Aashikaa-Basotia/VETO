import os
import uuid
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from gateway.gateway import app
from provenance.verifier import generate_provenance_signature

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_dbs():
    os.environ["VETO_AUDIT_DB"] = "test_xsrv_audit.db"
    os.environ["VETO_APPROVAL_DB"] = "test_xsrv_approval.db"
    os.environ["VETO_REPLAY_DB"] = "test_xsrv_replay.db"
    os.environ["VETO_CALENDAR_ACCESS_TOKEN"] = "mock"
    os.environ["VETO_GMAIL_ACCESS_TOKEN"] = "mock"
    
    import audit.logger
    audit.logger._audit_logger = None
    import approval.engine
    approval.engine._approval_engine = None
    import replay.engine
    replay.engine._replay_engine = None
    
    import sqlite3
    for db in ["test_xsrv_audit.db", "test_xsrv_approval.db", "test_xsrv_replay.db"]:
        try:
            with sqlite3.connect(db) as conn:
                for table in ["audit_logs", "audit_events", "approval_requests", "replay_state"]:
                    try:
                        conn.execute(f"DELETE FROM {table}")
                    except sqlite3.OperationalError:
                        pass
                conn.commit()
        except sqlite3.OperationalError:
            pass
    yield

def _sign_request(payload: dict, req_id: str = None) -> dict:
    if req_id is None:
        req_id = f"REQ-{uuid.uuid4()}"
    payload["request_id"] = req_id
    sig = generate_provenance_signature(payload["operation"], payload["arguments"], req_id)
    payload["provenance_signature"] = sig
    return payload

@patch('urllib.request.urlopen')
def test_scenario_a_gmail_to_calendar(mock_urlopen):
    """Scenario A: Gmail capability with Calendar destination."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "list_recent_emails",
        "arguments": {"max_results": 5}
    })
    payload["destination_override"] = "google_calendar_api"
    
    r = client.post("/gateway/execute", json=payload)
    assert r.status_code == 403
    assert r.json()["detail"]["decision"] == "BLOCK"
    assert "unknown_destination" in r.json()["detail"]["reason"]
    mock_urlopen.assert_not_called()

@patch('urllib.request.urlopen')
def test_scenario_b_calendar_to_gmail(mock_urlopen):
    """Scenario B: Calendar capability with Gmail destination."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "list_calendar_events",
        "arguments": {"max_results": 5}
    })
    payload["destination_override"] = "gmail_api"
    
    r = client.post("/gateway/execute", json=payload)
    assert r.status_code == 403
    assert r.json()["detail"]["decision"] == "BLOCK"
    mock_urlopen.assert_not_called()

@patch('urllib.request.urlopen')
def test_scenario_c_downstream_to_gmail(mock_urlopen):
    """Scenario C: Downstream capability with Gmail destination."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "get_downstream_status",
        "arguments": {}
    })
    payload["destination_override"] = "gmail_api"
    
    r = client.post("/gateway/execute", json=payload)
    assert r.status_code == 403
    mock_urlopen.assert_not_called()

@patch('urllib.request.urlopen')
def test_scenario_d_gmail_to_downstream(mock_urlopen):
    """Scenario D: Gmail capability with downstream destination."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "list_recent_emails",
        "arguments": {"max_results": 5}
    })
    payload["destination_override"] = "controlled_downstream"
    
    r = client.post("/gateway/execute", json=payload)
    assert r.status_code == 403
    mock_urlopen.assert_not_called()

@patch('urllib.request.urlopen')
def test_scenario_e_calendar_to_downstream(mock_urlopen):
    """Scenario E: Calendar capability with downstream destination."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "list_calendar_events",
        "arguments": {"max_results": 5}
    })
    payload["destination_override"] = "controlled_downstream"
    
    r = client.post("/gateway/execute", json=payload)
    assert r.status_code == 403
    mock_urlopen.assert_not_called()

def test_cross_service_provenance_tampering():
    """Changing operation after signing invalidates provenance."""
    # Sign for Gmail
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "list_recent_emails",
        "arguments": {"max_results": 5}
    })
    
    # Tamper to Calendar
    payload["operation"] = "list_calendar_events"
    
    r = client.post("/gateway/execute", json=payload)
    assert r.status_code == 403
    assert "provenance" in r.json()["detail"]["reason"].lower()
    
    # Sign for Calendar
    payload2 = _sign_request({
        "agent_id": "default_agent",
        "operation": "list_calendar_events",
        "arguments": {"max_results": 5}
    })
    
    # Tamper to Downstream
    payload2["operation"] = "create_record"
    payload2["arguments"] = {"name": "test", "value": "val"}
    
    r2 = client.post("/gateway/execute", json=payload2)
    assert r2.status_code == 403
    assert "provenance" in r2.json()["detail"]["reason"].lower()

@patch('urllib.request.urlopen')
def test_cross_service_replay_reuse(mock_urlopen):
    """A request ID consumed by one service cannot be reused for another."""
    req_id = f"REQ-{uuid.uuid4()}"
    
    # Exec 1: Calendar
    p1 = _sign_request({
        "agent_id": "default_agent",
        "operation": "create_calendar_event",
        "arguments": {"summary": "test", "start": {"date": "2026"}, "end": {"date": "2026"}}
    }, req_id=req_id)
    
    r1 = client.post("/gateway/execute", json=p1)
    assert r1.status_code == 403
    assert r1.json()["detail"]["decision"] == "REQUIRE_APPROVAL"
    
    # Exec 2: Try to reuse for Gmail
    p2 = _sign_request({
        "agent_id": "default_agent",
        "operation": "send_email",
        "arguments": {"to": "test@test.com", "subject": "a", "body": "b"}
    }, req_id=req_id)
    
    r2 = client.post("/gateway/execute", json=p2)
    assert r2.status_code == 403
    assert "replay" in r2.json()["detail"]["reason"].lower()

@patch('urllib.request.urlopen')
def test_cross_service_approval_reuse(mock_urlopen):
    """An approval for one operation cannot authorize another."""
    p1 = _sign_request({
        "agent_id": "default_agent",
        "operation": "create_calendar_event",
        "arguments": {"summary": "test", "start": {"date": "2026"}, "end": {"date": "2026"}}
    })
    r1 = client.post("/gateway/execute", json=p1)
    approval_id = r1.json()["detail"]["approval_id"]
    
    client.post(f"/approval/{approval_id}/approve")
    
    # Try to execute a different operation with that approval?
    # Wait, the approval engine doesn't let you supply approval_id in the request.
    # The gateway automatically calculates the request_hash and looks it up.
    # So if you submit `send_email`, it will calculate a DIFFERENT request_hash,
    # and find NO approval, thus returning REQUIRE_APPROVAL.
    p2 = _sign_request({
        "agent_id": "default_agent",
        "operation": "send_email",
        "arguments": {"to": "test@test.com", "subject": "a", "body": "b"}
    })
    r2 = client.post("/gateway/execute", json=p2)
    assert r2.status_code == 403
    assert r2.json()["detail"]["decision"] == "REQUIRE_APPROVAL"
    assert r2.json()["detail"]["approval_id"] != approval_id

def test_restricted_mode_escape_attempt():
    """Verify restricted execution mode blocks state-changing operations across ALL services."""
    ops = [
        ("create_record", {"name": "t", "value": "v"}),
        ("send_email", {"to": "t@t.com", "subject": "s", "body": "b"}),
        ("create_calendar_event", {"summary": "s", "start": {"date": "2026"}, "end": {"date": "2026"}})
    ]
    
    with patch.dict(os.environ, {"VETO_EXECUTION_MODE": "restricted"}):
        for op, args in ops:
            payload = _sign_request({
                "agent_id": "default_agent",
                "operation": op,
                "arguments": args
            })
            r = client.post("/gateway/execute", json=payload)
            assert r.status_code == 403
            assert "restricted" in r.json()["detail"]["reason"].lower()

def test_audit_logs_cross_service_blocks():
    """Audit correctly records blocked cross-service attempts."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "list_calendar_events",
        "arguments": {"max_results": 5}
    })
    payload["destination_override"] = "gmail_api"
    
    client.post("/gateway/execute", json=payload)
    
    from audit.logger import get_audit_logger
    logger = get_audit_logger()
    events = logger.get_events()
    last = events[-1]
    
    assert last.final_decision == "BLOCK"
    assert last.downstream_executed is False
    assert last.reason == "unknown_destination"

def test_no_secrets_exposed():
    """Ensure responses don't expose tokens."""
    payload = _sign_request({
        "agent_id": "default_agent",
        "operation": "list_calendar_events",
        "arguments": {"max_results": 5}
    })
    r = client.post("/gateway/execute", json=payload)
    # The error should be 500 (adapter error) since urlopen is not mocked here and token is 'mock', or actually gateway prevents token leak anyway.
    assert "mock" not in str(r.json())
    assert "token" not in str(r.json()).lower()
