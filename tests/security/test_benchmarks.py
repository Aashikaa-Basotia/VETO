import os
import json
import pytest
from unittest.mock import patch, MagicMock

from evaluator.benchmark import (
    VetoBenchmarkHarness,
    _compute_latency_summary,
    LatencySummary,
    BenchmarkReport
)
from evaluator.metrics import (
    calculate_metrics,
    ConfusionMatrix,
    OperationsSummary,
    MetricsReport
)
from attacks.runner import AttackRunResult

def test_latency_summary_statistics():
    """Verify statistical correctness of percentile, mean, min, max, and throughput calculation."""
    sample_data = [10.0, 12.0, 14.0, 16.0, 18.0, 20.0, 22.0, 24.0, 26.0, 28.0]
    total_wall_sec = 0.20 # 200ms total
    summary = _compute_latency_summary(sample_data, total_wall_sec)
    
    assert summary.count == 10
    assert summary.min_ms == 10.0
    assert summary.max_ms == 28.0
    assert summary.mean_ms == 19.0
    assert summary.median_ms == 19.0
    assert summary.p90_ms == 28.0
    assert summary.p95_ms == 28.0
    assert summary.p99_ms == 28.0
    assert summary.throughput_ops_per_sec == 50.0 # 10 ops / 0.2 sec

def test_empty_latency_summary():
    """Verify empty sample list returns safe zeroed metrics."""
    summary = _compute_latency_summary([], 0.0)
    assert summary.count == 0
    assert summary.mean_ms == 0.0
    assert summary.median_ms == 0.0
    assert summary.throughput_ops_per_sec == 0.0

def test_gateway_path_benchmarks_execution():
    """Quick run of gateway decision path benchmarks to verify non-zero measurements."""
    harness = VetoBenchmarkHarness(iterations=3, warmup=1)
    results = harness.run_gateway_benchmarks()
    
    expected_paths = [
        "gateway_fast_block_provenance",
        "gateway_capability_block",
        "gateway_destination_block",
        "gateway_context_block",
        "gateway_approval_flow",
        "gateway_allowed_read"
    ]
    
    for path in expected_paths:
        assert path in results
        lat = results[path].latency
        assert lat.count == 3
        assert lat.mean_ms > 0.0
        assert lat.min_ms <= lat.median_ms <= lat.max_ms

def test_micro_benchmarks_all_layers():
    """Verify that micro-benchmarking captures isolated layer latencies accurately."""
    harness = VetoBenchmarkHarness(iterations=3, warmup=1)
    results = harness.run_micro_benchmarks()
    
    expected_stages = [
        "micro_provenance_verification",
        "micro_replay_engine",
        "micro_capability_policy",
        "micro_destination_trust",
        "micro_risk_evaluation",
        "micro_context_evaluation",
        "micro_audit_logging"
    ]
    
    for stage in expected_stages:
        assert stage in results
        lat = results[stage].latency
        assert lat.count == 3
        assert lat.mean_ms > 0.0
        assert lat.min_ms <= lat.max_ms

def test_benchmark_database_isolation():
    """Benchmark executions must use isolated test databases and not touch production databases."""
    harness = VetoBenchmarkHarness(iterations=2, warmup=1)
    harness._setup_isolated_dbs()
    
    assert os.environ["VETO_APPROVAL_DB"] == "benchmark_approval.db"
    assert os.environ["VETO_AUDIT_DB"] == "benchmark_audit.db"
    assert os.environ["VETO_REPLAY_DB"] == "benchmark_replay.db"

def test_benchmark_report_serialization():
    """Verify full benchmark report creates a valid Pydantic model and serializes cleanly."""
    harness = VetoBenchmarkHarness(iterations=2, warmup=1)
    report = harness.execute_full_benchmark(export_path=None)
    
    assert isinstance(report, BenchmarkReport)
    assert report.environment.sample_iterations == 2
    assert "gateway_allowed_read" in report.gateway_benchmarks
    assert "micro_provenance_verification" in report.micro_benchmarks
    
    dump = report.model_dump_json()
    assert len(dump) > 0
    parsed = json.loads(dump)
    assert "gateway_benchmarks" in parsed
    assert "micro_benchmarks" in parsed

def test_end_to_end_separation():
    """Verify gateway-only measurements are clearly separated from external components."""
    harness = VetoBenchmarkHarness(iterations=2, warmup=1)
    comp = harness.run_end_to_end_comparison(gw_allowed_mean_ms=12.5)
    
    assert "gateway_vs_downstream_http" in comp
    assert "gateway_vs_llm_inference" in comp
    assert comp["gateway_vs_downstream_http"].gateway_only_mean_ms == 12.5
    assert comp["gateway_vs_llm_inference"].gateway_only_mean_ms == 12.5

def test_confusion_matrix_perfect_scenario():
    """Test confusion matrix with perfect security outcomes (100% TP and TN)."""
    attack = AttackRunResult(
        fixture_id="ATK-1",
        name="Attack",
        category="CAPABILITY",
        expected_decision="BLOCK",
        observed_decision="BLOCK",
        expected_block_stage="capability",
        observed_block_stage="capability",
        expected_downstream_contact=False,
        observed_downstream_contact=False,
        passed=True
    )
    control = AttackRunResult(
        fixture_id="CTRL-1",
        name="Control",
        category="CONTROL",
        expected_decision="ALLOW",
        observed_decision="ALLOW",
        expected_block_stage="none",
        observed_block_stage="none",
        expected_downstream_contact=True,
        observed_downstream_contact=True,
        passed=True
    )
    
    report = calculate_metrics([attack, control], [])
    cm = report.confusion_matrix
    
    assert cm.true_positives == 1
    assert cm.true_negatives == 1
    assert cm.false_positives == 0
    assert cm.false_negatives == 0
    assert cm.precision == 100.0
    assert cm.recall == 100.0
    assert cm.specificity == 100.0
    assert cm.f1_score == 100.0
    assert cm.accuracy == 100.0

def test_confusion_matrix_with_false_negatives():
    """Test confusion matrix when an attack slipped through (False Negative)."""
    slipped_attack = AttackRunResult(
        fixture_id="ATK-SLIP",
        name="Slipped Attack",
        category="CAPABILITY",
        expected_decision="BLOCK",
        observed_decision="ALLOW", # Erroneously allowed!
        expected_block_stage="capability",
        observed_block_stage="none",
        expected_downstream_contact=False,
        observed_downstream_contact=True, # Downstream contacted!
        passed=False
    )
    control = AttackRunResult(
        fixture_id="CTRL-1",
        name="Control",
        category="CONTROL",
        expected_decision="ALLOW",
        observed_decision="ALLOW",
        expected_block_stage="none",
        observed_block_stage="none",
        expected_downstream_contact=True,
        observed_downstream_contact=True,
        passed=True
    )
    
    report = calculate_metrics([slipped_attack, control], [])
    cm = report.confusion_matrix
    
    assert cm.true_positives == 0
    assert cm.false_negatives == 1
    assert cm.true_negatives == 1
    assert cm.false_positives == 0
    assert cm.recall == 0.0
    assert cm.accuracy == 50.0

def test_operations_decision_summary():
    """Verify operations breakdown accurately tallies allowed vs blocked operations."""
    res1 = AttackRunResult(
        fixture_id="ATK-CAP-001",
        name="Unauthorized Delete",
        category="CAPABILITY",
        expected_decision="BLOCK",
        observed_decision="BLOCK",
        expected_block_stage="capability",
        observed_block_stage="capability",
        expected_downstream_contact=False,
        observed_downstream_contact=False,
        passed=True
    )
    res2 = AttackRunResult(
        fixture_id="ATK-CTRL-001",
        name="Legitimate Read",
        category="CONTROL",
        expected_decision="ALLOW",
        observed_decision="ALLOW",
        expected_block_stage="none",
        observed_block_stage="none",
        expected_downstream_contact=True,
        observed_downstream_contact=True,
        passed=True
    )
    
    report = calculate_metrics([res1, res2], [])
    ops = report.operations_summary
    
    assert ops.total_operations_evaluated == 2
    assert ops.allowed_count == 1
    assert ops.blocked_count == 1
    assert ops.approval_required_count == 0
    assert "get_downstream_status" in ops.allowed_by_operation
    assert "delete_record" in ops.blocked_by_operation

def test_no_secrets_in_benchmark_report():
    """Ensure benchmark report model does not leak environment secrets."""
    harness = VetoBenchmarkHarness(iterations=2, warmup=1)
    report = harness.execute_full_benchmark(export_path=None)
    dump_str = report.model_dump_json()
    
    assert "VETO_PROVENANCE_SECRET" not in dump_str
    assert "default-dev-secret-12345" not in dump_str
    assert "VETO_GMAIL_ACCESS_TOKEN" not in dump_str
    assert "mock_token" not in dump_str

def test_api_evaluation_endpoint():
    """Verify GET /api/evaluation serves actual structured evaluation report."""
    from gateway.gateway import app
    from fastapi.testclient import TestClient
    client = TestClient(app)
    
    resp = client.get("/api/evaluation")
    assert resp.status_code == 200
    data = resp.json()
    assert "detection_rate" in data
    assert "prevention_rate" in data
    assert "false_allow" in data
    assert "false_block" in data
    assert "mutations_passed" in data
    assert "security_tests" in data
    assert "operators" in data

def test_api_benchmarks_endpoint():
    """Verify GET /api/benchmarks serves live latency benchmark report."""
    from gateway.gateway import app
    from fastapi.testclient import TestClient
    client = TestClient(app)
    
    resp = client.get("/api/benchmarks")
    assert resp.status_code == 200
    data = resp.json()
    assert "environment" in data
    assert "gateway_benchmarks" in data
    assert "micro_benchmarks" in data
    assert "end_to_end_comparison" in data
    assert "summary_highlights" in data
