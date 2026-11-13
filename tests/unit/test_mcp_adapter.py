import pytest
from unittest.mock import patch, MagicMock
import urllib.error
from mcp_servers.test_server import get_downstream_status, create_record

@patch('urllib.request.urlopen')
def test_get_downstream_status_success(mock_urlopen):
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"status": "ok"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    # In some MCP versions, @mcp.tool() returns the original function, 
    # in others it might be a wrapper. Let's try calling it directly.
    # Note: If it's async we might need to await it, but test_server.py defined it as sync.
    result = get_downstream_status()
    assert result == {"status": "ok"}

@patch('urllib.request.urlopen')
def test_get_downstream_status_error(mock_urlopen):
    mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
    
    result = get_downstream_status()
    assert "error" in result
    assert "Failed to connect" in result["error"]

@patch('urllib.request.urlopen')
def test_create_record_success(mock_urlopen):
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"created": true, "record_id": "REC-001"}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    result = create_record("test", "123")
    assert result == {"created": True, "record_id": "REC-001"}

