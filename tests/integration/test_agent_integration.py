import pytest
import sys
import os
import asyncio
from agent.agent import VetoAgent
from agent.mcp_client import VetoMCPClient
from agent.ollama_client import OllamaClient

def is_ollama_available():
    client = OllamaClient()
    return client.check_health()

@pytest.mark.skipif(not is_ollama_available(), reason="Ollama is not available or qwen3:8b not running")
def test_agent_integration():
    python_exe = sys.executable
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    server_path = os.path.join(root_dir, "backend", "mcp_servers", "test_server.py")
    if not os.path.exists(server_path):
        server_path = os.path.join(root_dir, "mcp_servers", "test_server.py")
    
    mcp_client = VetoMCPClient(command=python_exe, args=[server_path])
    agent = VetoAgent(mcp_client=mcp_client, model_name="qwen3:8b")
    
    # Send a request that should trigger the get_status tool
    result = asyncio.run(agent.async_process_request("What is the status of the test service?"))
    
    assert "[Agent] Tool result:" in result
    assert "VETO MCP test server" in result
    assert "ok" in result.lower()
