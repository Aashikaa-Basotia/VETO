import os
import json
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from gateway.gateway import app
from provenance.verifier import generate_provenance_signature
from audit.logger import get_audit_logger

# Use a test database for audit logging during demonstrations
os.environ["VETO_AUDIT_DB"] = "test_demo_audit.db"
os.environ["VETO_REPLAY_DB"] = "test_demo_replay.db"
client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_audit_db():
    import sqlite3
    db_path = "test_demo_audit.db"
    replay_path = "test_demo_replay.db"
    
    # Initialize logger
    import audit.logger
    audit.logger._audit_logger = None
    logger = get_audit_logger()
    
    import replay.engine
    replay.engine._replay_engine = None
    replay.engine.get_replay_engine()._init_db()
    
    # Clear the table before test
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM audit_events")
    conn.commit()
    conn.close()
    
    conn = sqlite3.connect(replay_path)
    try:
        conn.execute("DELETE FROM replay_state")
        conn.commit()
    except:
        pass
    conn.close()
    
    yield logger
    
    # Clear after test
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM audit_events")
    conn.commit()
    conn.close()
    
    conn = sqlite3.connect(replay_path)
    try:
        conn.execute("DELETE FROM replay_state")
        conn.commit()
    except:
        pass
    conn.close()

def get_last_audit_event(logger):
    events = logger.get_events()
    if not events:
        return None
    return events[-1]

# ---------------------------------------------------------
# Scenario A — Legitimate read
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_a_legitimate_read(mock_urlopen, clean_audit_db):
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"status": "ok"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    operation = "get_downstream_status"
    arguments = {}
    sig = generate_provenance_signature(operation, arguments, "REQ-97e0ff75-a433-4cef-ba12-8bdec64089f2")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "request_id": "REQ-97e0ff75-a433-4cef-ba12-8bdec64089f2",
        "provenance_signature": sig
    })
    
    assert response.status_code == 200
    mock_urlopen.assert_called_once()
    
    event = get_last_audit_event(clean_audit_db)
    assert event.provenance.verification == "VALID"
    assert event.capability.decision == "ALLOW"
    assert event.destination.trust == "TRUSTED"
    assert event.risk.level == "LOW"
    assert event.context.decision == "ALLOW"
    assert event.final_decision == "ALLOW"
    assert event.downstream_executed is True

# ---------------------------------------------------------
# Scenario B — Legitimate Gmail read
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_b_legitimate_gmail_read(mock_urlopen, clean_audit_db):
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"messages": []}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    operation = "list_recent_emails"
    arguments = {"max_results": 5}
    sig = generate_provenance_signature(operation, arguments, "REQ-e43cb2ee-de42-408c-8074-c16feadba9b2")
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "mock_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-e43cb2ee-de42-408c-8074-c16feadba9b2",
        "provenance_signature": sig
        })
        
    assert response.status_code == 200
    mock_urlopen.assert_called()
    
    event = get_last_audit_event(clean_audit_db)
    assert event.provenance.verification == "VALID"
    assert event.capability.decision == "ALLOW"
    assert event.destination.trust == "TRUSTED"
    assert event.risk.level == "LOW"
    assert event.context.decision == "ALLOW"
    assert event.final_decision == "ALLOW"
    assert event.downstream_executed is True

# ---------------------------------------------------------
# Scenario C — Unauthorized capability
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_c_unauthorized_capability(mock_urlopen, clean_audit_db):
    operation = "delete_record"
    arguments = {}
    sig = generate_provenance_signature(operation, arguments, "REQ-81e3cf0c-4323-427e-8f1d-ec8f39b90cbc")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "request_id": "REQ-81e3cf0c-4323-427e-8f1d-ec8f39b90cbc",
        "provenance_signature": sig
    })
    
    assert response.status_code == 403
    assert response.json()["detail"]["decision"] == "BLOCK"
    mock_urlopen.assert_not_called()
    
    event = get_last_audit_event(clean_audit_db)
    assert event.capability.decision == "BLOCK"
    assert event.final_decision == "BLOCK"
    assert event.downstream_executed is False
    assert event.destination is None  # NOT_EVALUATED

# ---------------------------------------------------------
# Scenario D — Unknown destination
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_d_unknown_destination(mock_urlopen, clean_audit_db):
    operation = "get_downstream_status"
    arguments = {}
    sig = generate_provenance_signature(operation, arguments, "REQ-765337d0-4c76-414a-85a2-71afc765a5bd")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "destination_override": "attacker_destination",
        "request_id": "REQ-765337d0-4c76-414a-85a2-71afc765a5bd",
        "provenance_signature": sig
    })
    
    assert response.status_code == 403
    mock_urlopen.assert_not_called()
    
    event = get_last_audit_event(clean_audit_db)
    assert event.capability.decision == "ALLOW"
    assert event.destination.trust == "UNKNOWN"
    assert event.final_decision == "BLOCK"
    assert event.downstream_executed is False

# ---------------------------------------------------------
# Scenario E — Arbitrary URL injection
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_e_arbitrary_url_injection(mock_urlopen, clean_audit_db):
    operation = "get_downstream_status"
    arguments = {}
    sig = generate_provenance_signature(operation, arguments, "REQ-d9f06482-e891-4ccc-804d-7c955af0ba43")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "destination_override": "http://127.0.0.1:9999",
        "request_id": "REQ-d9f06482-e891-4ccc-804d-7c955af0ba43",
        "provenance_signature": sig
    })
    
    assert response.status_code == 403
    mock_urlopen.assert_not_called()
    
    event = get_last_audit_event(clean_audit_db)
    assert event.final_decision == "BLOCK"
    assert event.downstream_executed is False

# ---------------------------------------------------------
# Scenario F — Missing provenance
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_f_missing_provenance(mock_urlopen, clean_audit_db):
    response = client.post("/gateway/execute", json={
        "operation": "get_downstream_status",
        "arguments": {}
    })
    
    assert response.status_code == 403
    mock_urlopen.assert_not_called()
    
    event = get_last_audit_event(clean_audit_db)
    assert event.provenance.verification == "INVALID"
    assert event.reason == "missing_provenance_signature"
    assert event.final_decision == "BLOCK"
    assert event.downstream_executed is False

# ---------------------------------------------------------
# Scenario G — Invalid provenance
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_g_invalid_provenance(mock_urlopen, clean_audit_db):
    response = client.post("/gateway/execute", json={
        "operation": "get_downstream_status",
        "arguments": {},
        "provenance_signature": "fake_bad_signature"
    })
    
    assert response.status_code == 403
    mock_urlopen.assert_not_called()
    
    event = get_last_audit_event(clean_audit_db)
    assert event.provenance.verification == "INVALID"
    assert event.final_decision == "BLOCK"
    assert event.downstream_executed is False

# ---------------------------------------------------------
# Scenario H — Tampered signed request
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_h_tampered_signed_request(mock_urlopen, clean_audit_db):
    operation = "send_email"
    arguments = {"to": "good@example.com", "subject": "Test", "body": "Test"}
    sig = generate_provenance_signature(operation, arguments, "REQ-a5163c58-96fe-460c-b0c2-89262ee3b696")
    
    # Tamper with the recipient after signing
    tampered_arguments = {"to": "evil@hacker.com", "subject": "Test", "body": "Test"}
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": tampered_arguments,
        "provenance_signature": sig
    })
    
    assert response.status_code == 403
    mock_urlopen.assert_not_called()
    
    event = get_last_audit_event(clean_audit_db)
    assert event.provenance.verification == "INVALID"
    assert event.final_decision == "BLOCK"
    assert event.downstream_executed is False

# ---------------------------------------------------------
# Scenario I — Restricted context
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_i_restricted_context(mock_urlopen, clean_audit_db):
    with patch.dict(os.environ, {"VETO_EXECUTION_MODE": "restricted"}):
        operation = "send_email"
        arguments = {"to": "good@example.com", "subject": "Test", "body": "Test"}
        sig = generate_provenance_signature(operation, arguments, "REQ-a5163c58-96fe-460c-b0c2-89262ee3b696")
        
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "execution_mode_override": "normal",
            "request_id": "REQ-a5163c58-96fe-460c-b0c2-89262ee3b696",
        "provenance_signature": sig
        })
        
        assert response.status_code == 403
        mock_urlopen.assert_not_called()
        
        event = get_last_audit_event(clean_audit_db)
        assert event.context.decision == "BLOCK"
        assert event.final_decision == "BLOCK"
        assert event.downstream_executed is False

# ---------------------------------------------------------
# Scenario J — Unauthorized Gmail write
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_j_unauthorized_gmail_write(mock_urlopen, clean_audit_db):
    operation = "delete_email"
    arguments = {"message_id": "123"}
    sig = generate_provenance_signature(operation, arguments, "REQ-10c43bca-32cf-476b-9fb7-82fdf9b17dcc")
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "mock_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-10c43bca-32cf-476b-9fb7-82fdf9b17dcc",
        "provenance_signature": sig
        })
        
    assert response.status_code == 403
    mock_urlopen.assert_not_called()
    
    event = get_last_audit_event(clean_audit_db)
    assert event.capability.decision == "BLOCK"
    assert event.final_decision == "BLOCK"
    assert event.downstream_executed is False

# ---------------------------------------------------------
# Scenario K — Arbitrary Gmail endpoint attempt
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_k_arbitrary_gmail_endpoint_attempt(mock_urlopen, clean_audit_db):
    # Try to make get_email_metadata do something else
    operation = "get_email_metadata"
    # By passing an arbitrary string containing path traversals, it should be blocked by validate_message_id
    arguments = {"message_id": "../../some-arbitrary-endpoint"}
    sig = generate_provenance_signature(operation, arguments, "REQ-fe67a673-9be8-4147-ada5-27468849d684")
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "mock_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-fe67a673-9be8-4147-ada5-27468849d684",
        "provenance_signature": sig
        })
        
    # The adapter raises ValueError, which gateway maps to 500
    assert response.status_code == 500
    assert "Malformed message ID" in response.json()["detail"]
    mock_urlopen.assert_not_called()
    
    event = get_last_audit_event(clean_audit_db)
    assert event.final_decision == "ALLOW" # It passed security policy
    assert event.downstream_executed is False # But execution failed
    assert event.reason == "gmail_api_error"

# ---------------------------------------------------------
# Scenario L — Authorized execution failure
# ---------------------------------------------------------
@patch('urllib.request.urlopen')
def test_scenario_l_authorized_execution_failure(mock_urlopen, clean_audit_db):
    from urllib.error import HTTPError
    
    # Mock an HTTP 401 Unauthorized from the Gmail API
    mock_urlopen.side_effect = HTTPError(
        url="https://gmail.googleapis.com", 
        code=401, 
        msg="Unauthorized", 
        hdrs={}, 
        fp=None
    )
    
    operation = "list_recent_emails"
    arguments = {"max_results": 5}
    sig = generate_provenance_signature(operation, arguments, "REQ-4caaf980-1c1d-48b2-97e8-ce26f6d278b2")
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "mock_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-4caaf980-1c1d-48b2-97e8-ce26f6d278b2",
        "provenance_signature": sig
        })
        
    assert response.status_code == 401
    mock_urlopen.assert_called_once()
    
    event = get_last_audit_event(clean_audit_db)
    assert event.provenance.verification == "VALID"
    assert event.capability.decision == "ALLOW"
    assert event.destination.trust == "TRUSTED"
    assert event.risk.level == "LOW"
    assert event.context.decision == "ALLOW"
    assert event.final_decision == "ALLOW"  # Security tests passed
    assert event.downstream_executed is True  # Reached the HTTP layer
    assert event.reason == "gmail_http_error_401"
