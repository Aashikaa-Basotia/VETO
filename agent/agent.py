import asyncio
import json
import sys
import os
from pydantic import BaseModel, ValidationError, Field
from typing import Optional, Any
from agent.mcp_client import VetoMCPClient
from agent.ollama_client import OllamaClient

class ToolCall(BaseModel):
    action: str = Field(pattern="^tool_call$")
    tool: str
    arguments: dict[str, Any]

class ResponseCall(BaseModel):
    action: str = Field(pattern="^respond$")
    response: str

class VetoAgent:
    def __init__(self, mcp_client: VetoMCPClient, model_name: str = "qwen3:8b"):
        self.mcp_client = mcp_client
        self.llm_client = OllamaClient(model=model_name)

    def process_request(self, user_request: str) -> str:
        return asyncio.run(self.async_process_request(user_request))

    async def async_process_request(self, user_request: str) -> str:
        # 1. System Prompt
        system_prompt = """You are a helpful AI agent with access to MCP tools.
You MUST respond using ONLY a valid JSON object in one of two formats:

Format 1 - Tool Call (use this to call a tool):
{"action": "tool_call", "tool": "get_status", "arguments": {}}

Format 2 - Direct Response (use this to respond to the user directly):
{"action": "respond", "response": "Your message here"}

Available Tools:
- get_status: Returns the current status of the VETO MCP test server. Takes no arguments.
- get_downstream_status: Returns the current status of the connected downstream service. Takes no arguments.
- create_record: Creates a new record in the downstream service. Arguments: "name" (string), "value" (string).
- delete_record: Deletes a record from the downstream service. Arguments: "record_id" (string).
- list_recent_emails: Lists recent emails from Gmail. Arguments: "max_results" (int).
- get_email_metadata: Retrieves metadata for a specific Gmail message. Arguments: "message_id" (string).
- get_email_body: Retrieves the body content of a specific Gmail message. Arguments: "message_id" (string).
- send_email: Sends an email using Gmail. Arguments: "to" (string), "subject" (string), "body" (string).

Do NOT include any Markdown formatting like ```json ... ```, just output the raw JSON object. Do not include any other text.
"""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_request}
        ]
        
        try:
            print("[Agent] Sending request to local LLM (qwen3:8b)...")
            response_text = self.llm_client.chat(messages, temperature=0.0)
            
            # 2. Parse Response
            clean_text = response_text.strip()
            if clean_text.startswith("```json"):
                clean_text = clean_text[7:]
            if clean_text.endswith("```"):
                clean_text = clean_text[:-3]
            clean_text = clean_text.strip()
            
            try:
                data = json.loads(clean_text)
            except json.JSONDecodeError:
                return f"[Agent Error] Model returned invalid JSON: {clean_text}"
                
            # 3. Validate
            if "action" not in data:
                return f"[Agent Error] Model returned JSON without 'action' field: {data}"
                
            if data["action"] == "tool_call":
                try:
                    tool_call = ToolCall(**data)
                except ValidationError as e:
                    return f"[Agent Error] Invalid tool call structure: {e}"
                    
                valid_tools = ["get_status", "get_downstream_status", "create_record", "delete_record", "list_recent_emails", "get_email_metadata", "get_email_body", "send_email"]
                if tool_call.tool in valid_tools:
                    print(f"[Agent] Validated tool request for '{tool_call.tool}'. Invoking MCP client...")
                    result = await self.mcp_client.invoke_tool(tool_call.tool, arguments=tool_call.arguments)
                    return f"[Agent] Tool result:\n{result}"
                else:
                    return f"[Agent Error] Unsupported tool requested: {tool_call.tool}"
            elif data["action"] == "respond":
                try:
                    response_call = ResponseCall(**data)
                except ValidationError as e:
                    return f"[Agent Error] Invalid response structure: {e}"
                return f"[Agent] LLM says: {response_call.response}"
            else:
                return f"[Agent Error] Unknown action: {data['action']}"
                
        except Exception as e:
            return f"[Agent Error] Failed during execution: {e}"

def main():
    if len(sys.argv) > 1:
        user_request = " ".join(sys.argv[1:])
    else:
        user_request = "What is the status of the test service?"
        
    python_exe = sys.executable
    root_dir = os.path.dirname(os.path.dirname(__file__))
    server_path = os.path.join(root_dir, "backend", "mcp_servers", "test_server.py")
    if not os.path.exists(server_path):
        server_path = os.path.join(root_dir, "mcp_servers", "test_server.py")
    
    mcp_client = VetoMCPClient(command=python_exe, args=[server_path])
    agent = VetoAgent(mcp_client=mcp_client)
    
    print(f"USER REQUEST: {user_request}\n")
    result = agent.process_request(user_request)
    print(result)

if __name__ == "__main__":
    main()
