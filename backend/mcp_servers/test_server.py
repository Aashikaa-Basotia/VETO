import os
import json
import uuid
import urllib.request
import urllib.error
from mcp.server.mcpserver import MCPServer
from provenance.verifier import generate_provenance_signature

mcp = MCPServer("veto_test_server")

# Trusted application configuration
VETO_GATEWAY_URL = os.environ.get("VETO_GATEWAY_URL", "http://127.0.0.1:8001")

def invoke_gateway(operation: str, arguments: dict = None) -> dict:
    if arguments is None:
        arguments = {}
    try:
        request_id = "REQ-" + str(uuid.uuid4())
        signature = generate_provenance_signature(operation, arguments, request_id)
        url = f"{VETO_GATEWAY_URL}/gateway/execute"
        data = json.dumps({
            "operation": operation, 
            "arguments": arguments,
            "request_id": request_id,
            "provenance_signature": signature
        }).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        try:
            error_msg = json.loads(e.read().decode('utf-8')).get('detail', str(e))
        except:
            error_msg = str(e)
        return {"error": f"Gateway HTTP Error: {error_msg}"}
    except urllib.error.URLError as e:
        return {"error": f"Failed to connect to gateway: {e}"}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def get_status() -> dict:
    """Returns the current status of the VETO MCP test server."""
    return {
        "status": "ok",
        "service": "VETO MCP test server"
    }

@mcp.tool()
def get_downstream_status() -> dict:
    """Returns the current status of the connected downstream service."""
    return invoke_gateway("get_downstream_status")

@mcp.tool()
def create_record(name: str, value: str) -> dict:
    """Creates a new record in the downstream service."""
    return invoke_gateway("create_record", {"name": name, "value": value})

@mcp.tool()
def delete_record(record_id: str) -> dict:
    """Deletes a record from the downstream service."""
    return invoke_gateway("delete_record", {"record_id": record_id})

@mcp.tool()
def list_recent_emails(max_results: int = 5) -> dict:
    """Lists recent emails from Gmail (metadata only, max 20)."""
    return invoke_gateway("list_recent_emails", {"max_results": max_results})

@mcp.tool()
def get_email_metadata(message_id: str) -> dict:
    """Retrieves metadata for a specific Gmail message."""
    return invoke_gateway("get_email_metadata", {"message_id": message_id})

@mcp.tool()
def get_email_body(message_id: str) -> dict:
    """Retrieves the body content of a specific Gmail message."""
    return invoke_gateway("get_email_body", {"message_id": message_id})

@mcp.tool()
def send_email(to: str, subject: str, body: str) -> dict:
    """Sends an email using Gmail."""
    return invoke_gateway("send_email", {"to": to, "subject": subject, "body": body})

@mcp.tool()
def list_calendar_events(max_results: int = 10, time_min: str = None, time_max: str = None) -> dict:
    """Lists calendar events."""
    args = {"max_results": max_results}
    if time_min:
        args["time_min"] = time_min
    if time_max:
        args["time_max"] = time_max
    return invoke_gateway("list_calendar_events", args)

@mcp.tool()
def create_calendar_event(summary: str, start: dict, end: dict, description: str = None) -> dict:
    """Creates a new calendar event."""
    args = {"summary": summary, "start": start, "end": end}
    if description:
        args["description"] = description
    return invoke_gateway("create_calendar_event", args)

if __name__ == "__main__":
    mcp.run()
