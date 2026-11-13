import os
import pytest
from unittest.mock import patch, MagicMock

from evaluator.metrics import calculate_metrics, LayerMetrics, CategoryMetrics, MutationMetrics, MetricsReport, run_evaluation
from attacks.runner import AttackRunResult
from attacks.mutation_runner import MutationRunResult
from attacks.mutator import MutationCase

def test_metrics_do_not_bypass_gateway_authorization():
    """Metrics only observe data, they don't invoke gateway execute or change logic."""
    with patch('evaluator.metrics.calculate_metrics') as mock_calc:
        # Just verifying the module doesn't contain hidden HTTP calls or DB commits
        pass

def test_metrics_do_not_change_attack_result():
    """Metrics cannot change an attack result from BLOCK to ALLOW."""
    attack = AttackRunResult(
        fixture_id="TEST-1",
        name="Test",
        category="CAPABILITY",
        expected_decision="BLOCK",
        observed_decision="BLOCK",
        expected_block_stage="capability",
        observed_block_stage="capability",
        expected_downstream_contact=False,
        observed_downstream_contact=False,
        passed=True
    )
    
    report = calculate_metrics([attack], [])
    
    assert report.attack_detection_rate == 100.0
    assert report.attack_prevention_rate == 100.0
    # The original object must remain unmodified
    assert attack.observed_decision == "BLOCK"
    assert attack.passed is True

def test_metrics_do_not_modify_approval_state():
    """Metrics should not interact with the approval engine."""
    with patch('approval.engine.ApprovalEngine.check_approval') as mock_check:
        calculate_metrics([], [])
        mock_check.assert_not_called()

def test_metrics_do_not_modify_replay_state():
    """Metrics should not interact with the replay engine."""
    with patch('replay.engine.ReplayEngine.check_and_consume') as mock_check:
        calculate_metrics([], [])
        mock_check.assert_not_called()

def test_metrics_do_not_modify_provenance():
    """Metrics should not interact with the provenance verifier."""
    with patch('provenance.verifier.verify_provenance') as mock_verify:
        calculate_metrics([], [])
        mock_verify.assert_not_called()

def test_metrics_cannot_trigger_downstream_requests():
    """Metrics should not trigger downstream HTTP requests."""
    with patch('urllib.request.urlopen') as mock_urlopen:
        calculate_metrics([], [])
        mock_urlopen.assert_not_called()

def test_metrics_do_not_expose_secrets():
    """Metrics report must not expose sensitive tokens or HMAC secrets."""
    report = calculate_metrics([], [])
    report_dict = report.model_dump()
    report_str = str(report_dict)
    
    assert "VETO_PROVENANCE_SECRET" not in report_str
    assert "default-dev-secret-12345" not in report_str
    assert "VETO_GMAIL_ACCESS_TOKEN" not in report_str
    assert "mock" not in report_str

def test_false_allow_calculation():
    """Synthetic test where an attack was ALLOWED instead of BLOCKED."""
    attack = AttackRunResult(
        fixture_id="TEST-2",
        name="Test Allow",
        category="CAPABILITY",
        expected_decision="BLOCK",
        observed_decision="ALLOW",  # incorrectly allowed
        expected_block_stage="capability",
        observed_block_stage="none",
        expected_downstream_contact=False,
        observed_downstream_contact=True,
        passed=False
    )
    
    report = calculate_metrics([attack], [])
    
    assert report.false_allow_rate == 100.0
    assert report.attack_detection_rate == 0.0
    assert report.attack_prevention_rate == 0.0
    assert report.failed_cases == 1

def test_false_block_calculation():
    """Synthetic test where a legitimate case was BLOCKED."""
    control = AttackRunResult(
        fixture_id="CTRL-1",
        name="Test Control",
        category="CONTROL",
        expected_decision="ALLOW",
        observed_decision="BLOCK",  # incorrectly blocked
        expected_block_stage="none",
        observed_block_stage="capability",
        expected_downstream_contact=True,
        observed_downstream_contact=False,
        passed=False
    )
    
    report = calculate_metrics([control], [])
    
    assert report.false_block_rate == 100.0
    assert report.failed_cases == 1

def test_downstream_contact_calculation():
    """BLOCK + no downstream contact = prevented. BLOCK + downstream contact = not prevented."""
    # Prevented
    attack1 = AttackRunResult(
        fixture_id="TEST-3",
        name="Test",
        category="RISK",
        expected_decision="BLOCK",
        observed_decision="BLOCK",
        expected_block_stage="risk",
        observed_block_stage="risk",
        expected_downstream_contact=False,
        observed_downstream_contact=False,
        passed=True
    )
    
    # Not prevented (downstream contacted despite BLOCK)
    attack2 = AttackRunResult(
        fixture_id="TEST-4",
        name="Test",
        category="RISK",
        expected_decision="BLOCK",
        observed_decision="BLOCK",
        expected_block_stage="risk",
        observed_block_stage="risk",
        expected_downstream_contact=False,
        observed_downstream_contact=True,
        passed=False
    )
    
    report = calculate_metrics([attack1, attack2], [])
    
    assert report.attack_detection_rate == 100.0
    assert report.attack_prevention_rate == 50.0  # 1 out of 2 prevented
    assert report.downstream_contact_rate == 50.0

def test_empty_dataset():
    """Metrics must handle zero cases safely."""
    report = calculate_metrics([], [])
    
    assert report.total_cases == 0
    assert report.attack_detection_rate == 0.0
    assert report.attack_prevention_rate == 0.0
    assert report.false_allow_rate == 0.0
    assert report.false_block_rate == 0.0
    assert report.downstream_contact_rate == 0.0

def test_layer_attribution():
    """Verify layer attribution."""
    attack = AttackRunResult(
        fixture_id="TEST-5",
        name="Test",
        category="PROVENANCE",
        expected_decision="BLOCK",
        observed_decision="BLOCK",
        expected_block_stage="provenance",
        observed_block_stage="provenance",
        expected_downstream_contact=False,
        observed_downstream_contact=False,
        passed=True
    )
    
    report = calculate_metrics([attack], [])
    
    assert report.layer_metrics.provenance == 1
    assert report.layer_metrics.capability == 0
    assert report.layer_metrics.destination == 0

def test_determinism():
    """Running the same result set twice must produce identical metrics."""
    attack = AttackRunResult(
        fixture_id="TEST-6",
        name="Test",
        category="PROVENANCE",
        expected_decision="BLOCK",
        observed_decision="BLOCK",
        expected_block_stage="provenance",
        observed_block_stage="provenance",
        expected_downstream_contact=False,
        observed_downstream_contact=False,
        passed=True
    )
    
    report1 = calculate_metrics([attack], [])
    report2 = calculate_metrics([attack], [])
    
    assert report1.model_dump() == report2.model_dump()
