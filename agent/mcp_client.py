import asyncio
import sys
import os
import json
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession

class VetoMCPClient:
    """
    Minimal MCP client for VETO Phase 2 testing.
    Connects to an MCP server via stdio and allows invoking tools.
    """
    def __init__(self, command: str, args: list[str]):
        # Ensure project root is in PYTHONPATH for the subprocess
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = os.environ.copy()
        env["PYTHONPATH"] = f"{project_root};{env.get('PYTHONPATH', '')}" if sys.platform == "win32" else f"{project_root}:{env.get('PYTHONPATH', '')}"
        
        self.server_parameters = StdioServerParameters(
            command=command,
            args=args,
            env=env
        )

    async def invoke_tool(self, tool_name: str, arguments: dict = None) -> str:
        """
        Connects to the server, discovers tools, and invokes the specified tool.
        Returns the parsed text output or raises an error.
        """
        if arguments is None:
            arguments = {}
            
        try:
            # 1 & 2. Launch the MCP test server and establish session
            async with stdio_client(self.server_parameters) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    
                    # 3. Discover/list the available tools
                    tools_response = await session.list_tools()
                    print(f"[Client] Discovered {len(tools_response.tools)} tools.")
                    for t in tools_response.tools:
                        print(f"  - {t.name}: {t.description}")
                    
                    # 4. Invoke the tool
                    print(f"[Client] Invoking tool '{tool_name}'...")
                    result = await session.call_tool(tool_name, arguments=arguments)
                    
                    # 5 & 6. Receive and structure the result
                    # 7. Clean shutdown happens automatically on exiting context managers
                    
                    # In mcp>=2.2.0, result.content is a list of TextContent or ImageContent.
                    if hasattr(result, "content") and result.content:
                        texts = []
                        for content in result.content:
                            if content.type == "text":
                                texts.append(content.text)
                        return "\n".join(texts)
                    return str(result)
        except Exception as e:
            print(f"[Client] Error communicating with MCP server: {e}", file=sys.stderr)
            raise

    async def invoke_get_status(self) -> str:
        return await self.invoke_tool("get_status")

async def main():
    python_exe = sys.executable
    root_dir = os.path.dirname(os.path.dirname(__file__))
    server_path = os.path.join(root_dir, "backend", "mcp_servers", "test_server.py")
    if not os.path.exists(server_path):
        server_path = os.path.join(root_dir, "mcp_servers", "test_server.py")
    
    if not os.path.exists(server_path):
        print(f"[Client] Error: Server script not found at {server_path}", file=sys.stderr)
        sys.exit(1)
        
    client = VetoMCPClient(command=python_exe, args=[server_path])
    
    try:
        result_text = await client.invoke_get_status()
        print("\n--- DEMONSTRATION RESULT ---")
        print(result_text)
    except Exception:
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
