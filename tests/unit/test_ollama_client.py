import pytest
from unittest.mock import patch, MagicMock
import urllib.error
from agent.ollama_client import OllamaClient

@patch('urllib.request.urlopen')
def test_ollama_client_chat_success(mock_urlopen):
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"model":"qwen3:8b","message":{"role":"assistant","content":"hello"}}'
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    client = OllamaClient()
    response = client.chat([{"role": "user", "content": "hi"}])
    assert response == "hello"

@patch('urllib.request.urlopen')
def test_ollama_client_chat_error(mock_urlopen):
    mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
    
    client = OllamaClient()
    with pytest.raises(Exception, match="Ollama connection error"):
        client.chat([{"role": "user", "content": "hi"}])

@patch('urllib.request.urlopen')
def test_ollama_client_health_check(mock_urlopen):
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    client = OllamaClient()
    assert client.check_health() is True
