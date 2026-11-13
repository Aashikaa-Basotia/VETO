from policy.engine import evaluate_capability, PolicyRequest, ALLOWED_CAPABILITIES

def test_allowed_capability():
    req = PolicyRequest(agent_id="default_agent", capability="get_downstream_status")
    decision = evaluate_capability(req)
    assert decision.decision == "ALLOW"
    assert decision.capability == "get_downstream_status"

def test_another_allowed_capability():
    req = PolicyRequest(agent_id="default_agent", capability="create_record", arguments={"name": "test", "value": "test"})
    decision = evaluate_capability(req)
    assert decision.decision == "ALLOW"
    assert decision.capability == "create_record"

def test_unknown_capability():
    req = PolicyRequest(agent_id="default_agent", capability="delete_record")
    decision = evaluate_capability(req)
    assert decision.decision == "BLOCK"
    assert "Capability not authorized" in decision.reason

def test_unknown_agent():
    req = PolicyRequest(agent_id="untrusted_agent", capability="get_downstream_status")
    decision = evaluate_capability(req)
    assert decision.decision == "BLOCK"
    assert "Unknown agent" in decision.reason

def test_missing_capability():
    req = PolicyRequest(agent_id="default_agent", capability="")
    decision = evaluate_capability(req)
    assert decision.decision == "BLOCK"
    assert "missing" in decision.reason.lower()

def test_malformed_policy_request():
    req = PolicyRequest(agent_id="", capability="create_record")
    decision = evaluate_capability(req)
    assert decision.decision == "BLOCK"
    assert "missing" in decision.reason.lower()
