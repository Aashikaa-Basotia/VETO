from context.evaluator import evaluate_context, SecurityContext, get_trusted_context

def test_valid_normal_context():
    context = SecurityContext(agent_id="default_agent", environment="local", execution_mode="normal")
    decision = evaluate_context("get_downstream_status", context)
    assert decision.decision == "ALLOW"
    
def test_valid_normal_context_state_changing():
    context = SecurityContext(agent_id="default_agent", environment="local", execution_mode="normal")
    decision = evaluate_context("create_record", context)
    assert decision.decision == "ALLOW"

def test_restricted_context_read_allowed():
    context = SecurityContext(agent_id="default_agent", environment="local", execution_mode="restricted")
    decision = evaluate_context("get_downstream_status", context)
    assert decision.decision == "ALLOW"

def test_restricted_context_state_changing_blocked():
    context = SecurityContext(agent_id="default_agent", environment="local", execution_mode="restricted")
    decision = evaluate_context("create_record", context)
    assert decision.decision == "BLOCK"
    assert "restricted" in decision.reason

def test_unknown_environment_blocked():
    context = SecurityContext(agent_id="default_agent", environment="unknown_env", execution_mode="normal")
    decision = evaluate_context("get_downstream_status", context)
    assert decision.decision == "BLOCK"
    assert "unknown_environment" in decision.reason

def test_unknown_execution_mode_blocked():
    context = SecurityContext(agent_id="default_agent", environment="local", execution_mode="unknown_mode")
    decision = evaluate_context("get_downstream_status", context)
    assert decision.decision == "BLOCK"
    assert "unknown_execution_mode" in decision.reason
    
def test_missing_required_context():
    # If somehow environment is empty
    context = SecurityContext(agent_id="default_agent", environment="", execution_mode="normal")
    decision = evaluate_context("get_downstream_status", context)
    assert decision.decision == "BLOCK"

def test_valid_context_must_not_override_capability_policy():
    # evaluate_context evaluates ONLY the context logic.
    # We test in the integration tests that evaluate_context is evaluated AFTER evaluate_capability.
    pass
