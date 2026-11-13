import pytest
import os
import uuid
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from gateway.gateway import app
from provenance.verifier import generate_provenance_signature
from approval.engine import get_approval_engine
from replay.engine import get_replay_engine
import sqlite3

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_dbs():
    os.environ["VETO_REPLAY_DB"] = "test_replay.db"
    os.environ["VETO_APPROVAL_DB"] = "test_approval.db"
    os.environ["VETO_AUDIT_DB"] = "test_audit.db"
    
    get_replay_engine()._init_db()
    get_approval_engine()._init_db()
    
    with sqlite3.connect("test_replay.db") as conn:
        conn.execute("DELETE FROM replay_state")
    with sqlite3.connect("test_approval.db") as conn:
        conn.execute("DELETE FROM approval_requests")
    
    yield

def make_request(op, args, req_id, override_sig=None, override_context=None):
    sig = override_sig if override_sig else generate_provenance_signature(op, args, req_id)
    payload = {
        "operation": op,
        "arguments": args,
        "provenance_signature": sig
    }
    if req_id is not None:
        payload["request_id"] = req_id
    if override_context:
        payload["execution_mode_override"] = override_context
    return client.post("/gateway/execute", json=payload)

@patch('urllib.request.urlopen')
def test_replay_first_use(mock_urlopen):
    # A. First-use success
    req_id = "REQ-REPLAY-001"
    
    # Pre-approve to let it hit downstream
    get_approval_engine().update_approval_status(
        get_approval_engine().create_approval_request("default_agent", "create_record", {"name":"t", "value":"v"}),
        "APPROVED"
    )
    
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"status": "ok"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    resp = make_request("create_record", {"name":"t", "value":"v"}, req_id)
    assert resp.status_code == 200
    assert mock_urlopen.called

@patch('urllib.request.urlopen')
def test_replay_exact_replay(mock_urlopen):
    # B. Exact replay
    req_id = "REQ-REPLAY-002"
    
    # Pre-approve
    get_approval_engine().update_approval_status(
        get_approval_engine().create_approval_request("default_agent", "create_record", {"name":"t", "value":"v"}),
        "APPROVED"
    )
    
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"status": "ok"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    resp1 = make_request("create_record", {"name":"t", "value":"v"}, req_id)
    assert resp1.status_code == 200
    
    mock_urlopen.reset_mock()
    resp2 = make_request("create_record", {"name":"t", "value":"v"}, req_id)
    
    assert resp2.status_code == 403
    assert resp2.json()["detail"]["reason"] == "replay_detected"
    assert not mock_urlopen.called

@patch('urllib.request.urlopen')
def test_replay_different_request_ids(mock_urlopen):
    # C. Different request IDs
    # Need multiple approvals for multiple requests
    get_approval_engine().update_approval_status(
        get_approval_engine().create_approval_request("default_agent", "create_record", {"name":"t", "value":"v"}),
        "APPROVED"
    )
    # The approval system bounds on hash without request_id, so one approval covers both requests if args are the same!
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"status": "ok"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    resp1 = make_request("create_record", {"name":"t", "value":"v"}, "REQ-003A")
    assert resp1.status_code == 200
    
    resp2 = make_request("create_record", {"name":"t", "value":"v"}, "REQ-003B")
    assert resp2.status_code == 200

def test_replay_tampered_request():
    # D. Tampered request
    req_id = "REQ-004"
    valid_sig = generate_provenance_signature("create_record", {"name":"t", "value":"v"}, req_id)
    resp = make_request("create_record", {"name":"t", "value":"tampered"}, req_id, override_sig=valid_sig)
    assert resp.status_code == 403
    assert "tampered_or_invalid" in resp.json()["detail"]["reason"]

def test_replay_missing_identifier():
    # E. Missing replay identifier
    resp = make_request("create_record", {"name":"t", "value":"v"}, None)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "missing_request_id"

def test_replay_invalid_identifier():
    # F. Invalid replay identifier
    # Currently defined as missing. If it's an empty string, it should block.
    resp = make_request("create_record", {"name":"t", "value":"v"}, "")
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "missing_request_id"

def test_replay_cross_operation():
    # G. Cross-operation reuse
    req_id = "REQ-007"
    get_replay_engine().check_and_consume(req_id, "default_agent", "create_record")
    resp = make_request("send_email", {"to":"x", "subject":"y", "body":"z"}, req_id)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "replay_detected"

def test_replay_cross_agent():
    # H. Cross-agent reuse
    req_id = "REQ-008"
    get_replay_engine().check_and_consume(req_id, "other_agent", "create_record")
    resp = make_request("create_record", {"name":"t", "value":"v"}, req_id)
    # The current engine hashes request_id globally across all agents for safety (as PK).
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "replay_detected"

def test_replay_approval_persistence():
    # I. Approval + replay
    req_id = "REQ-009"
    get_approval_engine().update_approval_status(
        get_approval_engine().create_approval_request("default_agent", "create_record", {"name":"t", "value":"v"}),
        "APPROVED"
    )
    with patch('urllib.request.urlopen') as mock_urlopen:
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"status": "ok"}'
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response
        
        make_request("create_record", {"name":"t", "value":"v"}, req_id)
        mock_urlopen.reset_mock()
        
        resp2 = make_request("create_record", {"name":"t", "value":"v"}, req_id)
        assert resp2.status_code == 403
        assert resp2.json()["detail"]["reason"] == "replay_detected"
        assert not mock_urlopen.called

def test_replay_restricted_context():
    # J. Restricted context + replay
    req_id = "REQ-010"
    with patch.dict(os.environ, {"VETO_EXECUTION_MODE": "restricted"}):
        resp = make_request("create_record", {"name":"t", "value":"v"}, req_id)
    assert resp.status_code == 403
    assert "state_changing" in resp.json()["detail"]["reason"]

def test_replay_unauthorized_capability():
    # K. Unauthorized capability
    req_id = "REQ-011"
    resp = make_request("delete_record", {}, req_id)
    assert resp.status_code == 403
    assert "not authorized" in resp.json()["detail"]["reason"]

def test_replay_unknown_destination():
    # L. Unknown destination
    req_id = "REQ-012"
    sig = generate_provenance_signature("create_record", {"name":"t", "value":"v"}, req_id)
    resp = client.post("/gateway/execute", json={
        "operation": "create_record",
        "arguments": {"name":"t", "value":"v"},
        "request_id": req_id,
        "provenance_signature": sig,
        "destination_override": "evil"
    })
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "unknown_destination"

@patch('urllib.request.urlopen')
def test_replay_gmail_send(mock_urlopen):
    # M. Gmail send replay
    req_id = "REQ-GMAIL-001"
    get_approval_engine().update_approval_status(
        get_approval_engine().create_approval_request("default_agent", "send_email", {"to":"x", "subject":"y", "body":"z"}),
        "APPROVED"
    )
    
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"id": "msg123"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "mock"}):
        resp1 = make_request("send_email", {"to":"x", "subject":"y", "body":"z"}, req_id)
        assert resp1.status_code == 200
        
        mock_urlopen.reset_mock()
        resp2 = make_request("send_email", {"to":"x", "subject":"y", "body":"z"}, req_id)
        assert resp2.status_code == 403
        assert resp2.json()["detail"]["reason"] == "replay_detected"
        assert not mock_urlopen.called

def test_replay_secret_leakage():
    # O. Secret leakage
    req_id = "REQ-LEAK-001"
    resp = make_request("create_record", {"name":"t", "value":"v"}, req_id)
    out = json.dumps(resp.json())
    assert "VETO_PROVENANCE_SECRET" not in out
    assert "VETO_GMAIL_ACCESS_TOKEN" not in out
