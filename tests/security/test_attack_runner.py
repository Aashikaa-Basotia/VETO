import pytest
from unittest.mock import patch, MagicMock
from attacks.runner import run_all_fixtures, AttackRunResult
from attacks.fixtures import ATTACK_FIXTURES

def test_runner_coverage():
    results = run_all_fixtures()
    assert len(results) == len(ATTACK_FIXTURES), "Runner must evaluate all fixtures"

def test_result_schema():
    results = run_all_fixtures()
    for result in results:
        assert isinstance(result, AttackRunResult)
        assert isinstance(result.fixture_id, str)
        assert isinstance(result.passed, bool)

def test_all_fixtures_pass():
    # If VETO is correctly configured, all baseline fixtures must pass
    results = run_all_fixtures()
    for result in results:
        assert result.passed is True, f"Fixture {result.fixture_id} failed: Expected {result.expected_decision}/{result.expected_block_stage}, got {result.observed_decision}/{result.observed_block_stage}"
        assert result.error is None

def test_downstream_verification():
    # Ensure blocked fixtures report downstream_contact = False
    results = run_all_fixtures()
    for result in results:
        if result.expected_decision in ["BLOCK", "REQUIRE_APPROVAL"]:
            assert result.observed_downstream_contact is False

def test_determinism():
    results1 = run_all_fixtures()
    results2 = run_all_fixtures()
    
    assert [r.fixture_id for r in results1] == [r.fixture_id for r in results2]
    assert [r.passed for r in results1] == [r.passed for r in results2]

@patch('attacks.runner.TestClient.post')
def test_error_handling(mock_post):
    mock_post.side_effect = Exception("Simulated runner crash")
    
    results = run_all_fixtures()
    assert len(results) == len(ATTACK_FIXTURES)
    
    for result in results:
        assert result.passed is False
        assert result.observed_decision == "ERROR"
        assert result.observed_block_stage == "error"
        assert "Simulated runner crash" in result.error

def test_no_secret_leakage():
    results = run_all_fixtures()
    for result in results:
        output_str = str(result.model_dump())
        assert "VETO_GMAIL_ACCESS_TOKEN" not in output_str
        assert "VETO_PROVENANCE_SECRET" not in output_str
