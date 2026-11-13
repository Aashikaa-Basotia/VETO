import os
import json
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from gateway.gateway import app
from provenance.verifier import generate_provenance_signature
from audit.logger import get_audit_logger
from approval.engine import get_approval_engine

# Use a test database for audit logging and approval during demonstrations
os.environ["VETO_AUDIT_DB"] = "test_approval_audit.db"
os.environ["VETO_APPROVAL_DB"] = "test_approval_db.db"
os.environ["VETO_REPLAY_DB"] = "test_replay.db"
client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_dbs():
    import sqlite3
    db_path_audit = "test_approval_audit.db"
    db_path_appr = "test_approval_db.db"
    db_path_replay = "test_replay.db"
    
    # Initialize logger
    import audit.logger
    audit.logger._audit_logger = None
    logger = get_audit_logger()
    
    # Initialize engine
    import approval.engine
    approval.engine._approval_engine = None
    engine = get_approval_engine()
    
    import replay.engine
    replay.engine._replay_engine = None
    
    tables = [
        (db_path_audit, "audit_events"), 
        (db_path_appr, "approval_requests"),
        (db_path_replay, "replay_state")
    ]
    
    # Clear tables
    for path, table in tables:
        import sqlite3
        conn = sqlite3.connect(path)
        try:
            conn.execute(f"DELETE FROM {table}")
            conn.commit()
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
            
    yield logger, engine

def get_last_audit_event(logger):
    events = logger.get_events()
    return events[-1] if events else None

# A. Read does not require approval
@patch('urllib.request.urlopen')
def test_a_read_does_not_require_approval(mock_urlopen, clean_dbs):
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"status": "ok"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    operation = "get_downstream_status"
    arguments = {}
    sig = generate_provenance_signature(operation, arguments, "REQ-f8bac850-9bb4-4f0f-9eb7-9f54cdbebfa6")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "request_id": "REQ-f8bac850-9bb4-4f0f-9eb7-9f54cdbebfa6",
        "provenance_signature": sig
    })
    
    assert response.status_code == 200
    mock_urlopen.assert_called_once()
    
    event = get_last_audit_event(clean_dbs[0])
    assert event.final_decision == "ALLOW"
    assert event.downstream_executed is True

# B. create_record requires approval
@patch('urllib.request.urlopen')
def test_b_create_record_requires_approval(mock_urlopen, clean_dbs):
    operation = "create_record"
    arguments = {"name": "test", "value": "val"}
    sig = generate_provenance_signature(operation, arguments, "REQ-66110dd0-3c03-4a44-b1dd-6be8f44b4df0")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "request_id": "REQ-66110dd0-3c03-4a44-b1dd-6be8f44b4df0",
        "provenance_signature": sig
    })
    
    assert response.status_code == 403
    assert response.json()["detail"]["decision"] == "REQUIRE_APPROVAL"
    assert "approval_id" in response.json()["detail"]
    mock_urlopen.assert_not_called()

# C. send_email requires approval
@patch('urllib.request.urlopen')
def test_c_send_email_requires_approval(mock_urlopen, clean_dbs):
    operation = "send_email"
    arguments = {"to": "test@test.com", "subject": "Test", "body": "test"}
    sig = generate_provenance_signature(operation, arguments, "REQ-02f78589-518c-42bf-91dd-9f24e9dbb1dd")
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "mock"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-02f78589-518c-42bf-91dd-9f24e9dbb1dd",
        "provenance_signature": sig
        })
        
    assert response.status_code == 403
    assert response.json()["detail"]["decision"] == "REQUIRE_APPROVAL"
    mock_urlopen.assert_not_called()

# D. Approval can be granted
def test_d_approval_can_be_granted(clean_dbs):
    logger, engine = clean_dbs
    appr_id = engine.create_approval_request("default_agent", "send_email", {})
    response = client.post(f"/approval/{appr_id}/approve")
    
    assert response.status_code == 200
    assert response.json() == {"status": "APPROVED"}
    assert engine.get_approval_status(appr_id) == "APPROVED"
    
    event = get_last_audit_event(logger)
    assert event.operation == "approve_request"
    assert event.approval.status == "APPROVED"

# E. Approved request executes
@patch('urllib.request.urlopen')
def test_e_approved_request_executes(mock_urlopen, clean_dbs):
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"created": true}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    operation = "create_record"
    arguments = {"name": "test", "value": "val"}
    sig1 = generate_provenance_signature(operation, arguments, "REQ-1")
    
    # 1. First attempt -> REQUIRES_APPROVAL
    res1 = client.post("/gateway/execute", json={
        "operation": operation, "arguments": arguments, "request_id": "REQ-1",
        "provenance_signature": sig1
    })
    appr_id = res1.json()["detail"]["approval_id"]
    
    # 2. Approve
    client.post(f"/approval/{appr_id}/approve")
    
    # 3. Second attempt -> ALLOW (must use fresh replay ID since first was consumed)
    sig2 = generate_provenance_signature(operation, arguments, "REQ-2")
    res2 = client.post("/gateway/execute", json={
        "operation": operation, "arguments": arguments, "request_id": "REQ-2",
        "provenance_signature": sig2
    })
    
    assert res2.status_code == 200
    mock_urlopen.assert_called_once()
    
    event = get_last_audit_event(clean_dbs[0])
    assert event.final_decision == "ALLOW"
    assert event.approval.status == "APPROVED"

# F. Rejected approval does not execute
@patch('urllib.request.urlopen')
def test_f_rejected_approval_does_not_execute(mock_urlopen, clean_dbs):
    operation = "create_record"
    arguments = {"name": "test", "value": "val"}
    sig1 = generate_provenance_signature(operation, arguments, "REQ-F-1")
    
    # 1. First attempt -> REQUIRES_APPROVAL
    res1 = client.post("/gateway/execute", json={
        "operation": operation, "arguments": arguments, "request_id": "REQ-F-1",
        "provenance_signature": sig1
    })
    appr_id = res1.json()["detail"]["approval_id"]
    
    # 2. Reject
    client.post(f"/approval/{appr_id}/reject")
    
    # 3. Second attempt -> REQUIRES_APPROVAL (because there is no APPROVED record)
    sig2 = generate_provenance_signature(operation, arguments, "REQ-F-2")
    res2 = client.post("/gateway/execute", json={
        "operation": operation, "arguments": arguments, "request_id": "REQ-F-2",
        "provenance_signature": sig2
    })
    
    assert res2.status_code == 403
    assert res2.json()["detail"]["decision"] == "REQUIRE_APPROVAL"
    mock_urlopen.assert_not_called()

# G. Pending approval does not execute
@patch('urllib.request.urlopen')
def test_g_pending_approval_does_not_execute(mock_urlopen, clean_dbs):
    operation = "create_record"
    arguments = {"name": "test", "value": "val"}
    sig1 = generate_provenance_signature(operation, arguments, "REQ-G-1")
    
    res1 = client.post("/gateway/execute", json={
        "operation": operation, "arguments": arguments, "request_id": "REQ-G-1",
        "provenance_signature": sig1
    })
    
    # Second attempt without human action -> REQUIRES_APPROVAL
    sig2 = generate_provenance_signature(operation, arguments, "REQ-G-2")
    res2 = client.post("/gateway/execute", json={
        "operation": operation, "arguments": arguments, "request_id": "REQ-G-2",
        "provenance_signature": sig2
    })
    
    assert res2.status_code == 403
    mock_urlopen.assert_not_called()

# H. Tampered request after approval
@patch('urllib.request.urlopen')
def test_h_tampered_request_after_approval(mock_urlopen, clean_dbs):
    operation = "create_record"
    args1 = {"name": "test", "value": "val1"}
    sig1 = generate_provenance_signature(operation, args1, "REQ-H-1")
    
    res1 = client.post("/gateway/execute", json={
        "operation": operation, "arguments": args1, "request_id": "REQ-H-1", "provenance_signature": sig1
    })
    client.post(f"/approval/{res1.json()['detail']['approval_id']}/approve")
    
    args2 = {"name": "test", "value": "val2"} # tampered
    sig2 = generate_provenance_signature(operation, args2, "REQ-H-2")
    
    res2 = client.post("/gateway/execute", json={
        "operation": operation, "arguments": args2, "request_id": "REQ-H-2", "provenance_signature": sig2
    })
    
    assert res2.status_code == 403
    assert res2.json()["detail"]["decision"] == "REQUIRE_APPROVAL"
    mock_urlopen.assert_not_called()

# I. Approval cannot bypass invalid provenance
@patch('urllib.request.urlopen')
def test_i_approval_cannot_bypass_invalid_provenance(mock_urlopen, clean_dbs):
    operation = "create_record"
    arguments = {"name": "test", "value": "val"}
    sig1 = generate_provenance_signature(operation, arguments, "REQ-I-1")
    
    res1 = client.post("/gateway/execute", json={
        "operation": operation, "arguments": arguments, "request_id": "REQ-I-1",
        "provenance_signature": sig1
    })
    client.post(f"/approval/{res1.json()['detail']['approval_id']}/approve")
    
    res2 = client.post("/gateway/execute", json={
        "operation": operation, "arguments": arguments, "request_id": "REQ-I-2", "provenance_signature": "bad_sig"
    })
    
    assert res2.status_code == 403
    assert res2.json()["detail"]["decision"] == "BLOCK"
    assert "provenance" in res2.json()["detail"]["reason"]
    mock_urlopen.assert_not_called()

# J. Approval cannot bypass restricted context
@patch('urllib.request.urlopen')
def test_j_approval_cannot_bypass_restricted_context(mock_urlopen, clean_dbs):
    operation = "create_record"
    arguments = {"name": "test", "value": "val"}
    sig1 = generate_provenance_signature(operation, arguments, "REQ-J-1")
    
    # Do normal context to get approval
    res1 = client.post("/gateway/execute", json={
        "operation": operation, "arguments": arguments, "request_id": "REQ-J-1",
        "provenance_signature": sig1
    })
    client.post(f"/approval/{res1.json()['detail']['approval_id']}/approve")
    
    # Now try to execute under restricted context
    sig2 = generate_provenance_signature(operation, arguments, "REQ-J-2")
    with patch.dict(os.environ, {"VETO_EXECUTION_MODE": "restricted"}):
        res2 = client.post("/gateway/execute", json={
            "operation": operation, "arguments": arguments, "request_id": "REQ-J-2",
            "provenance_signature": sig2
        })
        
    assert res2.status_code == 403
    assert res2.json()["detail"]["decision"] == "BLOCK"
    assert "state_changing" in res2.json()["detail"]["reason"]
    mock_urlopen.assert_not_called()

# K. Approval cannot bypass unauthorized capability
@patch('urllib.request.urlopen')
def test_k_approval_cannot_bypass_unauthorized_capability(mock_urlopen, clean_dbs):
    # Hack the DB to inject an approval for an unauthorized capability
    operation = "delete_record"
    arguments = {}
    
    engine = clean_dbs[1]
    appr_id = engine.create_approval_request("default_agent", operation, arguments)
    engine.update_approval_status(appr_id, "APPROVED")
    
    sig = generate_provenance_signature(operation, arguments, "REQ-c706e98d-5f35-4945-8b4d-9b6c1af5df04")
    res = client.post("/gateway/execute", json={
        "operation": operation, "arguments": arguments, "request_id": "REQ-c706e98d-5f35-4945-8b4d-9b6c1af5df04",
        "provenance_signature": sig
    })
    
    assert res.status_code == 403
    assert "authorized" in res.json()["detail"]["reason"]
    mock_urlopen.assert_not_called()

# L. Approval cannot bypass unknown destination
@patch('urllib.request.urlopen')
def test_l_approval_cannot_bypass_unknown_destination(mock_urlopen, clean_dbs):
    operation = "create_record"
    arguments = {"name": "test", "value": "val"}
    
    engine = clean_dbs[1]
    appr_id = engine.create_approval_request("default_agent", operation, arguments)
    engine.update_approval_status(appr_id, "APPROVED")
    
    sig = generate_provenance_signature(operation, arguments, "REQ-947f6609-5296-4f60-acde-72f0f263c1ce")
    res = client.post("/gateway/execute", json={
        "operation": operation, "arguments": arguments, "destination_override": "hacker", "request_id": "REQ-947f6609-5296-4f60-acde-72f0f263c1ce",
        "provenance_signature": sig
    })
    
    assert res.status_code == 403
    assert "unknown_destination" in res.json()["detail"]["reason"]
    mock_urlopen.assert_not_called()

# M. Approval endpoint cannot approve nonexistent request
def test_m_approval_endpoint_fails_nonexistent():
    res = client.post("/approval/fake/approve")
    assert res.status_code == 400

# N. Double approval is deterministic
def test_n_double_approval_deterministic(clean_dbs):
    appr_id = clean_dbs[1].create_approval_request("default_agent", "create_record", {})
    res1 = client.post(f"/approval/{appr_id}/approve")
    assert res1.status_code == 200
    
    res2 = client.post(f"/approval/{appr_id}/approve")
    assert res2.status_code == 400  # already approved (only transitions from PENDING)

# O. Reject after approval fails explicitly
def test_o_reject_after_approval_fails(clean_dbs):
    appr_id = clean_dbs[1].create_approval_request("default_agent", "create_record", {})
    client.post(f"/approval/{appr_id}/approve")
    
    res2 = client.post(f"/approval/{appr_id}/reject")
    assert res2.status_code == 400  # cannot reject APPROVED request

# P. Secret leakage
def test_p_secret_leakage(clean_dbs):
    appr_id = clean_dbs[1].create_approval_request("default_agent", "create_record", {})
    res = client.post(f"/approval/{appr_id}/approve")
    body = res.json()
    assert "SECRET" not in str(body)
    assert "TOKEN" not in str(body)
