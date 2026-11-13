from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from gateway.gateway import app
from provenance.verifier import generate_provenance_signature
import os

client = TestClient(app)

@patch('urllib.request.urlopen')
def test_gateway_get_downstream_status(mock_urlopen):
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"status": "ok"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    operation = "get_downstream_status"
    arguments = {}
    sig = generate_provenance_signature(operation, arguments, "REQ-930674a2-c5af-4700-bb97-8dfb75591722")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "request_id": "REQ-930674a2-c5af-4700-bb97-8dfb75591722",
        "provenance_signature": sig
    })
    
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    
@patch('approval.engine.requires_approval', return_value=False)
@patch('urllib.request.urlopen')
def test_gateway_create_record(mock_urlopen, mock_requires_approval):
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"created": true, "record_id": "REC-001"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    operation = "create_record"
    arguments = {"name": "test-name", "value": "test-value"}
    sig = generate_provenance_signature(operation, arguments, "REQ-b9d51ee4-ae2d-42d3-bbcf-d208b2cfcd07")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "request_id": "REQ-b9d51ee4-ae2d-42d3-bbcf-d208b2cfcd07",
        "provenance_signature": sig
    })
    
    assert response.status_code == 200
    assert response.json() == {"created": True, "record_id": "REC-001"}

@patch('urllib.request.urlopen')
def test_gateway_unsupported_operation(mock_urlopen):
    operation = "delete_record"
    arguments = {}
    sig = generate_provenance_signature(operation, arguments, "REQ-b43e6898-c883-4194-95ee-0e0f495e5d8c")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "request_id": "REQ-b43e6898-c883-4194-95ee-0e0f495e5d8c",
        "provenance_signature": sig
    })
    assert response.status_code == 403
    assert response.json()["detail"]["decision"] == "BLOCK"
    assert "Capability not authorized" in response.json()["detail"]["reason"]
    mock_urlopen.assert_not_called()

@patch('approval.engine.requires_approval', return_value=False)
def test_gateway_missing_args(mock_requires_approval):
    operation = "create_record"
    arguments = {"name": "test-name"}
    sig = generate_provenance_signature(operation, arguments, "REQ-998fe508-2c7e-4872-bd2a-54b96b06a1ad")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "request_id": "REQ-998fe508-2c7e-4872-bd2a-54b96b06a1ad",
        "provenance_signature": sig
    })
    assert response.status_code == 400
    assert response.json()["detail"]["decision"] == "BLOCK"
    assert "missing_required_arguments" in response.json()["detail"]["reason"]

@patch('urllib.request.urlopen')
def test_gateway_unknown_destination_bypass(mock_urlopen):
    operation = "get_downstream_status"
    arguments = {}
    sig = generate_provenance_signature(operation, arguments, "REQ-6209abcb-fb3c-4008-be75-016196cd6b65")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "destination_override": "http://evil.com",
        "request_id": "REQ-6209abcb-fb3c-4008-be75-016196cd6b65",
        "provenance_signature": sig
    })
    
    assert response.status_code == 403
    assert response.json()["detail"]["decision"] == "BLOCK"
    assert "unknown_destination" in response.json()["detail"]["reason"]
    mock_urlopen.assert_not_called()

@patch('urllib.request.urlopen')
def test_gateway_context_blocks_state_changing(mock_urlopen):
    with patch.dict(os.environ, {"VETO_EXECUTION_MODE": "restricted"}):
        operation = "create_record"
        arguments = {"name": "test-name", "value": "test-value"}
        sig = generate_provenance_signature(operation, arguments, "REQ-a9ae098e-9182-477d-81a8-9c6a2239f5fd")
        
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-a9ae098e-9182-477d-81a8-9c6a2239f5fd",
        "provenance_signature": sig
        })
        
        assert response.status_code == 403
        assert response.json()["detail"]["decision"] == "BLOCK"
        assert "state_changing" in response.json()["detail"]["reason"]
        mock_urlopen.assert_not_called()

@patch('urllib.request.urlopen')
def test_gateway_context_manipulation_protection(mock_urlopen):
    with patch.dict(os.environ, {"VETO_EXECUTION_MODE": "restricted"}):
        operation = "create_record"
        arguments = {"name": "test-name", "value": "test-value"}
        sig = generate_provenance_signature(operation, arguments, "REQ-54463e4e-c7bd-484a-9faa-15f548421648")
        
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "execution_mode_override": "normal",
            "request_id": "REQ-54463e4e-c7bd-484a-9faa-15f548421648",
        "provenance_signature": sig
        })
        
        assert response.status_code == 403
        assert response.json()["detail"]["decision"] == "BLOCK"
        assert "state_changing" in response.json()["detail"]["reason"]
        mock_urlopen.assert_not_called()

@patch('urllib.request.urlopen')
def test_gateway_provenance_missing(mock_urlopen):
    response = client.post("/gateway/execute", json={
        "operation": "get_downstream_status",
        "arguments": {}
    })
    assert response.status_code == 403
    assert response.json()["detail"]["decision"] == "BLOCK"
    assert "missing_provenance" in response.json()["detail"]["reason"]
    mock_urlopen.assert_not_called()

@patch('urllib.request.urlopen')
def test_gateway_provenance_invalid(mock_urlopen):
    response = client.post("/gateway/execute", json={
        "operation": "get_downstream_status",
        "arguments": {},
        "provenance_signature": "invalid_signature_123"
    })
    assert response.status_code == 403
    assert response.json()["detail"]["decision"] == "BLOCK"
    assert "invalid_provenance" in response.json()["detail"]["reason"]
    mock_urlopen.assert_not_called()

@patch('urllib.request.urlopen')
def test_gateway_provenance_tampered_payload(mock_urlopen):
    # Agent tries to sign get_status, but actually asks for create_record
    sig = generate_provenance_signature("get_downstream_status", {})
    
    response = client.post("/gateway/execute", json={
        "operation": "create_record",
        "arguments": {"name": "evil", "value": "data"},
        "provenance_signature": sig
    })
    assert response.status_code == 403
    assert response.json()["detail"]["decision"] == "BLOCK"
    assert "invalid_provenance" in response.json()["detail"]["reason"]
    mock_urlopen.assert_not_called()
