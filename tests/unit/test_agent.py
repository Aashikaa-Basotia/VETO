import pytest
from unittest.mock import Mock, patch
from agent.agent import VetoAgent, ToolCall, ResponseCall
from pydantic import ValidationError

@pytest.fixture
def mock_mcp_client():
    return Mock()

def test_tool_call_validation():
    tc = ToolCall(action="tool_call", tool="get_status", arguments={})
    assert tc.tool == "get_status"
    
    with pytest.raises(ValidationError):
        ToolCall(action="respond", tool="get_status", arguments={})

def test_response_call_validation():
    rc = ResponseCall(action="respond", response="hello")
    assert rc.response == "hello"
    
    with pytest.raises(ValidationError):
        ResponseCall(action="tool_call", response="hello")

@patch('agent.agent.OllamaClient')
def test_agent_tool_call(mock_ollama_class):
    from unittest.mock import AsyncMock
    mock_mcp_client = AsyncMock()
    mock_ollama = mock_ollama_class.return_value
    mock_ollama.chat.return_value = '{"action": "tool_call", "tool": "get_status", "arguments": {}}'
    mock_mcp_client.invoke_tool.return_value = "STATUS OK"
    
    import asyncio
    async def run_test():
        agent = VetoAgent(mcp_client=mock_mcp_client)
        result = await agent.async_process_request("status?")
        assert "[Agent] Tool result:" in result
        assert "STATUS OK" in result
    
    asyncio.run(run_test())

@patch('agent.agent.OllamaClient')
def test_agent_invalid_json(mock_ollama_class, mock_mcp_client):
    mock_ollama = mock_ollama_class.return_value
    mock_ollama.chat.return_value = 'this is not json'
    
    agent = VetoAgent(mcp_client=mock_mcp_client)
    result = agent.process_request("hello?")
    assert "[Agent Error] Model returned invalid JSON" in result

@patch('agent.agent.OllamaClient')
def test_agent_unsupported_tool(mock_ollama_class, mock_mcp_client):
    mock_ollama = mock_ollama_class.return_value
    mock_ollama.chat.return_value = '{"action": "tool_call", "tool": "delete_all", "arguments": {}}'
    
    agent = VetoAgent(mcp_client=mock_mcp_client)
    result = agent.process_request("delete")
    assert "[Agent Error] Unsupported tool requested" in result

@patch('agent.agent.OllamaClient')
def test_agent_normal_response(mock_ollama_class, mock_mcp_client):
    mock_ollama = mock_ollama_class.return_value
    mock_ollama.chat.return_value = '{"action": "respond", "response": "Hello world!"}'
    
    agent = VetoAgent(mcp_client=mock_mcp_client)
    result = agent.process_request("say hello")
    assert "[Agent] LLM says: Hello world!" in result
