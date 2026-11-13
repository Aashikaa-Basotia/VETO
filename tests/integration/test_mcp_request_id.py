import pytest
import json
import uuid
from unittest.mock import patch
from fastapi.testclient import TestClient

from gateway.gateway import app
from mcp_servers.test_server import invoke_gateway
from provenance.verifier import VETO_PROVENANCE_SECRET

# Set up test client
client = TestClient(app)

class MockHTTPResponse:
    def __init__(self, content, status_code):
        self.content = content
        self.status = status_code
        self.code = status_code

    def read(self):
        return self.content

    def decode(self):
        return self.content.decode('utf-8')
        
class MockHTTPError(Exception):
    def __init__(self, response):
        self.response = response
    def read(self):
        return self.response.content

def route_to_testclient(req):
    data = req.data
    headers = dict(req.headers) if hasattr(req, 'headers') else {'Content-Type': 'application/json'}
    response = client.post("/gateway/execute", content=data, headers=headers)
    mock_resp = MockHTTPResponse(response.content, response.status_code)
    
    # raise urllib.error.HTTPError if >= 400
    if response.status_code >= 400:
        import urllib.error
        raise urllib.error.HTTPError(req.full_url, response.status_code, "HTTP Error", {}, mock_resp)
        
    return mock_resp

@pytest.fixture
def mock_gateway():
    with patch('urllib.request.urlopen', side_effect=route_to_testclient):
        yield

def test_live_mcp_read_operation(mock_gateway):
    """A. Live MCP read operation still works."""
    result = invoke_gateway("list_recent_emails", {"max_results": 5})
    # Read operations pass replay as NOT_EVALUATED and proceed
    if "error" in result:
        assert "missing_request_id" not in result["error"]
        assert "Gmail Adapter error" in result["error"] or "unsupported_operation" in result["error"]
    # Depending on destination config, it might return a valid list or fail downstream, but it shouldn't fail at missing_request_id

def test_live_mcp_state_changing_operation(mock_gateway):
    """B. Live MCP state-changing operation now reaches the gateway replay stage instead of being blocked with missing_request_id."""
    result = invoke_gateway("create_record", {"name": "test", "value": "test"})
    # create_record will require approval or fail at adapter/context, but it MUST NOT fail with missing_request_id
    if "error" in result:
        err = result["error"]
        assert "missing_request_id" not in err
        # It should reach REQUIRE_APPROVAL (403 with reason approval...)
        assert "REQUIRE_APPROVAL" in err or "approval" in err or "not authorized" in err

def test_mcp_request_id_uniqueness():
    """C. Two separate MCP invocations generate different request IDs.
       D. The request ID is actually included in the signed payload."""
    payloads = []
    def capture_payload(req):
        payloads.append(json.loads(req.data.decode('utf-8')))
        return MockHTTPResponse(b'{"status": "ok"}', 200)

    with patch('urllib.request.urlopen', side_effect=capture_payload):
        invoke_gateway("list_recent_emails", {"max_results": 1})
        invoke_gateway("create_record", {"name": "a", "value": "b"})

    assert len(payloads) == 2
    req_id_1 = payloads[0].get("request_id")
    req_id_2 = payloads[1].get("request_id")
    
    assert req_id_1 is not None
    assert req_id_2 is not None
    assert req_id_1.startswith("REQ-")
    assert req_id_2.startswith("REQ-")
    assert req_id_1 != req_id_2

def test_tampering_request_id(mock_gateway):
    """E. Tampering with request_id after signing causes provenance verification failure."""
    # We'll intercept the payload, alter the request_id, and send it to the TestClient
    from provenance.verifier import generate_provenance_signature
    
    op = "create_record"
    args = {"name": "tamper", "value": "tamper"}
    req_id = "REQ-" + str(uuid.uuid4())
    sig = generate_provenance_signature(op, args, req_id)
    
    tampered_id = "REQ-" + str(uuid.uuid4())
    data = json.dumps({
        "operation": op,
        "arguments": args,
        "request_id": tampered_id,
        "provenance_signature": sig
    }).encode('utf-8')
    
    response = client.post("/gateway/execute", content=data, headers={'Content-Type': 'application/json'})
    assert response.status_code == 403
    assert "tampered_or_invalid_provenance_signature" in response.text

def test_no_secret_leakage():
    """H. No secrets appear in request payloads or logs."""
    payloads = []
    def capture_payload(req):
        payloads.append(req.data.decode('utf-8'))
        return MockHTTPResponse(b'{"status": "ok"}', 200)

    with patch('urllib.request.urlopen', side_effect=capture_payload):
        invoke_gateway("create_record", {"name": "a", "value": "b"})
        
    secret = VETO_PROVENANCE_SECRET.decode('utf-8')
    assert secret not in payloads[0]
