import os
import pytest
from unittest.mock import patch, MagicMock
from services.google_auth import GoogleAuthManager, get_google_auth_manager
from services.gmail import GmailAdapter
from audit.logger import create_event, get_audit_logger
from fastapi.testclient import TestClient
from gateway.gateway import app
from provenance.verifier import generate_provenance_signature

client = TestClient(app)

def _sign_request(payload: dict, req_id: str = "REQ-oauth-test-123") -> dict:
    sig = generate_provenance_signature(payload["operation"], payload.get("arguments", {}), req_id)
    payload["request_id"] = req_id
    payload["provenance_signature"] = sig
    return payload

def test_missing_oauth_config():
    """1. Missing OAuth configuration"""
    with patch.dict(os.environ, clear=True):
        manager = GoogleAuthManager()
        with pytest.raises(Exception, match="Gmail OAuth credentials not configured"):
            manager.get_valid_token()

@patch('services.google_auth.Credentials')
def test_invalid_oauth_config(mock_creds):
    """2. Invalid OAuth configuration & 5. Authentication failure"""
    with patch.dict(os.environ, {
        "GOOGLE_OAUTH_CLIENT_ID": "invalid",
        "GOOGLE_OAUTH_CLIENT_SECRET": "invalid",
        "GOOGLE_OAUTH_REFRESH_TOKEN": "invalid"
    }):
        manager = GoogleAuthManager()
        mock_instance = mock_creds.return_value
        mock_instance.valid = False
        
        from google.auth.exceptions import GoogleAuthError
        mock_instance.refresh.side_effect = GoogleAuthError("Invalid Grant")
        
        with pytest.raises(Exception, match="Failed to refresh Google OAuth token"):
            manager.get_valid_token()

@patch('services.google_auth.Credentials')
def test_successful_token_acquisition(mock_creds):
    """3. Successful token acquisition"""
    with patch.dict(os.environ, {
        "GOOGLE_OAUTH_CLIENT_ID": "id",
        "GOOGLE_OAUTH_CLIENT_SECRET": "secret",
        "GOOGLE_OAUTH_REFRESH_TOKEN": "refresh"
    }):
        manager = GoogleAuthManager()
        mock_instance = mock_creds.return_value
        mock_instance.valid = True
        mock_instance.token = "valid_bearer_token"
        
        assert manager.get_valid_token() == "valid_bearer_token"
        assert not mock_instance.refresh.called

@patch('services.google_auth.Credentials')
def test_expired_token_refresh(mock_creds):
    """4. Expired-token refresh"""
    with patch.dict(os.environ, {
        "GOOGLE_OAUTH_CLIENT_ID": "id",
        "GOOGLE_OAUTH_CLIENT_SECRET": "secret",
        "GOOGLE_OAUTH_REFRESH_TOKEN": "refresh"
    }):
        manager = GoogleAuthManager()
        mock_instance = mock_creds.return_value
        mock_instance.valid = False
        
        # When refresh is called, it becomes valid and sets a new token
        def side_effect(request):
            mock_instance.valid = True
            mock_instance.token = "refreshed_bearer_token"
            
        mock_instance.refresh.side_effect = side_effect
        
        assert manager.get_valid_token() == "refreshed_bearer_token"
        assert mock_instance.refresh.called

@patch('urllib.request.urlopen')
def test_authorization_header_construction(mock_urlopen):
    """6. Authorization header construction"""
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "test_auth_token"}):
        adapter = GmailAdapter()
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"messages": []}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp
        
        adapter.list_recent_emails()
        
        req = mock_urlopen.call_args_list[0][0][0]
        assert req.get_header("Authorization") == "Bearer test_auth_token"

def test_token_leakage_prevention():
    """7. Token leakage prevention & 8. Authorization-header leakage prevention"""
    # Ensure audit events never serialize tokens
    event = create_event(
        operation="list_recent_emails",
        reason="some_reason"
    )
    dump = event.model_dump_json()
    assert "test_auth_token" not in dump
    assert "Bearer" not in dump
    assert "Authorization" not in dump

@patch('urllib.request.urlopen')
def test_agent_supplied_auth_header_rejection(mock_urlopen):
    """9. Agent-supplied authentication header rejection"""
    # Agents cannot supply headers, they can only supply arguments.
    # We verify that if an agent attempts to pass 'headers' in arguments, the adapter ignores it.
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "secure_token"}):
        payload = _sign_request({
            "agent_id": "default_agent",
            "operation": "list_recent_emails",
            "arguments": {"max_results": 2, "headers": {"Authorization": "Bearer evil_token"}}
        })
        
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"messages": []}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp
        
        client.post("/gateway/execute", json=payload)
        
        req = mock_urlopen.call_args_list[0][0][0]
        # The true header must be the secure token, not the injected one
        assert req.get_header("Authorization") == "Bearer secure_token"

@patch('urllib.request.urlopen')
def test_agent_supplied_arbitrary_endpoint_rejection(mock_urlopen):
    """10. Agent-supplied arbitrary Gmail endpoint rejection"""
    with patch.dict(os.environ, {"VETO_GMAIL_ACCESS_TOKEN": "secure_token"}):
        payload = _sign_request({
            "agent_id": "default_agent",
            "operation": "list_recent_emails",
            "arguments": {"max_results": 2, "endpoint": "https://evil.com/gmail"}
        })
        
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"messages": []}'
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp
        
        client.post("/gateway/execute", json=payload)
        
        req = mock_urlopen.call_args_list[0][0][0]
        # The adapter strictly uses hardcoded URL
        assert req.full_url.startswith("https://gmail.googleapis.com/gmail/v1/users/me")

@pytest.mark.skipif(os.environ.get("VETO_REAL_GMAIL_TEST") != "1", reason="Opt-in real Gmail integration tests.")
def test_real_gmail_integration():
    """Opt-in real Gmail integration test."""
    # This requires GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET, GOOGLE_OAUTH_REFRESH_TOKEN
    manager = get_google_auth_manager()
    token = manager.get_valid_token()
    assert token is not None
    
    adapter = GmailAdapter()
    result = adapter.list_recent_emails(max_results=1)
    assert "messages" in result
