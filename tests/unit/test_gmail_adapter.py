import os
import json
import pytest
from unittest.mock import patch, MagicMock
import uuid
from gateway.gateway import app
from fastapi.testclient import TestClient
from provenance.verifier import generate_provenance_signature

client = TestClient(app)

@patch('urllib.request.urlopen')
def test_gmail_adapter_valid_request(mock_urlopen):
    operation = "list_recent_emails"
    arguments = {"max_results": 2}
    sig = generate_provenance_signature(operation, arguments, "REQ-0bef5af6-f280-47a6-af9c-d18295b83454")
    
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"messages": [{"id": "1"}, {"id": "2"}]}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "fake_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-0bef5af6-f280-47a6-af9c-d18295b83454",
        "provenance_signature": sig
        })
        
    assert response.status_code == 200
    assert response.json()["status"] == "SUCCESS"
    assert len(response.json()["messages"]) == 2

@patch('urllib.request.urlopen')
def test_gmail_adapter_missing_credentials(mock_urlopen):
    operation = "list_recent_emails"
    arguments = {"max_results": 2}
    sig = generate_provenance_signature(operation, arguments, "REQ-56e43a1e-e670-4ef0-b29b-12c56926ecbd")
    
    # Intentionally empty environment dict
    with patch.dict(os.environ, {}, clear=True):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-56e43a1e-e670-4ef0-b29b-12c56926ecbd",
        "provenance_signature": sig
        })
        
    assert response.status_code == 500
    assert "Gmail OAuth credentials not configured" in response.json()["detail"]

def test_gmail_adapter_direct_bypass():
    # Calling the adapter without provenance must fail closed
    operation = "list_recent_emails"
    arguments = {"max_results": 2}
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments
    })
    
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "missing_provenance_signature"

def test_gmail_adapter_unauthorized_capability():
    operation = "delete_email"
    arguments = {}
    sig = generate_provenance_signature(operation, arguments, "REQ-7f9877ef-f4fe-4254-8530-c4fa12a8cc47")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "request_id": "REQ-7f9877ef-f4fe-4254-8530-c4fa12a8cc47",
        "provenance_signature": sig
    })
    
    assert response.status_code == 403
    assert "Capability not authorized" in response.json()["detail"]["reason"]

def test_gmail_adapter_unknown_destination_override():
    operation = "list_recent_emails"
    arguments = {"max_results": 2}
    sig = generate_provenance_signature(operation, arguments, "REQ-79c8a4f2-9fcb-46cf-be55-89e92ef3e311")
    
    response = client.post("/gateway/execute", json={
        "operation": operation,
        "arguments": arguments,
        "destination_override": "untrusted_gmail",
        "request_id": "REQ-79c8a4f2-9fcb-46cf-be55-89e92ef3e311",
        "provenance_signature": sig
    })
    
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "unknown_destination"

@patch('urllib.request.urlopen')
def test_gmail_adapter_bounds_checking(mock_urlopen):
    # Test that >20 max_results is bounded to 20
    operation = "list_recent_emails"
    arguments = {"max_results": 100}
    sig = generate_provenance_signature(operation, arguments, "REQ-4598ec2c-07d0-4043-90af-cac7c80eea34")
    
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"messages": []}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "fake_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-4598ec2c-07d0-4043-90af-cac7c80eea34",
        "provenance_signature": sig
        })
        
    assert response.status_code == 200
    
    # We inspect the actual call arguments to mock_urlopen
    # The first call should have maxResults=20
    first_call_req = mock_urlopen.call_args_list[0][0][0]
    assert "maxResults=20" in first_call_req.full_url

@patch('urllib.request.urlopen')
def test_gmail_adapter_get_metadata_valid(mock_urlopen):
    operation = "get_email_metadata"
    arguments = {"message_id": "msg_123"}
    sig = generate_provenance_signature(operation, arguments, "REQ-bd142391-5cee-4f45-a511-110d6e6792fb")
    
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"id": "msg_123", "snippet": "Hello", "payload": {"headers": [{"name": "Subject", "value": "Test Subject"}]}}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "fake_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-bd142391-5cee-4f45-a511-110d6e6792fb",
        "provenance_signature": sig
        })
        
    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["message"]["id"] == "msg_123"
    assert response.json()["message"]["subject"] == "Test Subject"

@patch('urllib.request.urlopen')
def test_gmail_adapter_get_body_valid(mock_urlopen):
    operation = "get_email_body"
    arguments = {"message_id": "msg_123"}
    sig = generate_provenance_signature(operation, arguments, "REQ-a03a94c8-7124-4059-8376-ad99179360e7")
    
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"id": "msg_123", "snippet": "Hello", "payload": {"body": {"data": "SGVsbG8gV29ybGQ="}}}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "fake_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-a03a94c8-7124-4059-8376-ad99179360e7",
        "provenance_signature": sig
        })
        
    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["message"]["body_data"] == "SGVsbG8gV29ybGQ="

def test_gmail_adapter_missing_message_id():
    operation = "get_email_metadata"
    arguments = {}
    sig = generate_provenance_signature(operation, arguments, "REQ-d1ce2894-d17d-4ab4-ba58-930345c5a414")
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "fake_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-d1ce2894-d17d-4ab4-ba58-930345c5a414",
        "provenance_signature": sig
        })
        
    assert response.status_code == 400
    assert response.json()["detail"]["reason"] == "missing_message_id"

def test_gmail_adapter_malformed_message_id():
    # Attempt to inject path traversal via message ID
    operation = "get_email_metadata"
    arguments = {"message_id": "../settings"}
    sig = generate_provenance_signature(operation, arguments, "REQ-e0360d84-d30b-4bf0-85d7-541dab7025d0")
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "fake_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": "REQ-e0360d84-d30b-4bf0-85d7-541dab7025d0",
        "provenance_signature": sig
        })
        
    assert response.status_code == 500
    assert "Malformed message ID" in response.json()["detail"]

@patch('approval.engine.requires_approval', return_value=False)
@patch('urllib.request.urlopen')
def test_gmail_adapter_send_email_valid(mock_urlopen, mock_appr):
    operation = "send_email"
    arguments = {"to": "test@example.com", "subject": "Test", "body": "Hello"}
    request_id = f"REQ-{uuid.uuid4()}"
    sig = generate_provenance_signature(operation, arguments, request_id)
    
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"id": "sent_123", "threadId": "thread_123"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "fake_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": request_id,
        "provenance_signature": sig
        })
        
    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["id"] == "sent_123"
    
    req = mock_urlopen.call_args_list[0][0][0]
    assert req.method == "POST"
    assert req.full_url == "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"

@patch('approval.engine.requires_approval', return_value=False)
def test_gmail_adapter_send_email_injection(mock_appr):
    operation = "send_email"
    arguments = {"to": "test@example.com\r\nBcc: hacker@evil.com", "subject": "Test", "body": "Hello"}
    request_id = f"REQ-{uuid.uuid4()}"
    sig = generate_provenance_signature(operation, arguments, request_id)
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "fake_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
            "request_id": request_id,
        "provenance_signature": sig
        })
        
    assert response.status_code == 500
    assert "invalid control characters" in response.json()["detail"]

@patch('approval.engine.requires_approval', return_value=False)
def test_gmail_adapter_send_email_large_body(mock_appr):
    operation = "send_email"
    arguments = {"to": "test@example.com", "subject": "Test", "body": "A" * (101 * 1024)}
    request_id = f"REQ-{uuid.uuid4()}"
    sig = generate_provenance_signature(operation, arguments, request_id)
    
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "fake_token"}):
        response = client.post("/gateway/execute", json={
            "operation": operation,
            "arguments": arguments,
                            "request_id": request_id,
        "provenance_signature": sig
        })
        
    assert response.status_code == 500
    assert "maximum size" in response.json()["detail"]
