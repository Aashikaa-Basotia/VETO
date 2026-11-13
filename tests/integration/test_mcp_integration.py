import os
import sys
import json
import asyncio
import pytest
from agent.mcp_client import VetoMCPClient

def get_server_path():
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    backend_path = os.path.join(root_dir, "backend", "mcp_servers", "test_server.py")
    if os.path.exists(backend_path):
        return backend_path
    return os.path.join(
        root_dir, 
        "mcp_servers", 
        "test_server.py"
    )

def test_mcp_client_server_communication():
    """
    Tests that:
    1. The MCP server can start.
    2. The MCP client can connect through stdio.
    3. The client can discover the test tool.
    4. The client can invoke get_status.
    5. The returned result contains the expected deterministic status.
    6. The MCP session shuts down cleanly.
    """
    server_path = get_server_path()
    assert os.path.exists(server_path), "Test server script must exist"
    
    client = VetoMCPClient(command=sys.executable, args=[server_path])
    
    async def run_test():
        result_text = await client.invoke_get_status()
        result_dict = json.loads(result_text)
        assert result_dict.get("status") == "ok"
        assert result_dict.get("service") == "VETO MCP test server"
        
    # Run the async test in a new event loop
    asyncio.run(run_test())

def test_mcp_client_connection_error_handling():
    """
    Tests that the client handles connection failures cleanly (e.g. invalid server script).
    """
    invalid_path = "non_existent_server_file.py"
    client = VetoMCPClient(command=sys.executable, args=[invalid_path])
    
    async def run_error_test():
        with pytest.raises(Exception):
            await client.invoke_get_status()
            
    asyncio.run(run_error_test())
