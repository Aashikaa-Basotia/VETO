import os
import json
from unittest.mock import patch, MagicMock
from audit.logger import get_audit_logger, AuditLogger, AuditEvent
from gateway.gateway import app
from fastapi.testclient import TestClient
from provenance.verifier import generate_provenance_signature

client = TestClient(app)

def test_audit_successful_request():
    test_db = "test_audit_success.db"
    
    with patch.dict(os.environ, {"VETO_AUDIT_DB": test_db}):
        import audit.logger
        audit.logger._audit_logger = None
        
        operation = "get_downstream_status"
        arguments = {}
        sig = generate_provenance_signature(operation, arguments)
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = b'{"status": "ok"}'
            mock_response.__enter__.return_value = mock_response
            mock_urlopen.return_value = mock_response

            response = client.post("/gateway/execute", json={
                "operation": operation,
                "arguments": arguments,
                "provenance_signature": sig
            })
            
        assert response.status_code == 200
        
        logger = get_audit_logger()
        events = logger.get_events()
        
        # Only get the event for this operation
        # Since db persists across tests if run together, just find ours
        event = [e for e in events if e.operation == operation][-1]
        
        assert event.operation == operation
        assert event.final_decision == "ALLOW"
        assert event.downstream_executed is True
        assert event.provenance.verification == "VALID"
        assert event.capability.decision == "ALLOW"
        assert event.destination.trust == "TRUSTED"
        assert event.risk.level == "LOW"
        assert event.context.decision == "ALLOW"

def test_audit_blocked_request():
    test_db = "test_audit_blocked.db"
    
    with patch.dict(os.environ, {"VETO_AUDIT_DB": test_db}):
        import audit.logger
        audit.logger._audit_logger = None
        
        response = client.post("/gateway/execute", json={
            "operation": "get_downstream_status",
            "arguments": {}
        })
        
        assert response.status_code == 403
        
        logger = get_audit_logger()
        events = logger.get_events()
        
        event = [e for e in events if e.reason == "missing_provenance_signature"][-1]
        
        assert event.operation == "get_downstream_status"
        assert event.final_decision == "BLOCK"
        assert event.downstream_executed is False
        assert event.provenance.verification == "INVALID"
        assert event.reason == "missing_provenance_signature"
