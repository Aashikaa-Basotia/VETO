import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from attacks.runner import run_all_fixtures, AttackRunResult
from attacks.mutation_runner import run_mutations, MutationRunResult
from attacks.fixtures import ATTACK_FIXTURES

class LayerMetrics(BaseModel):
    provenance: int = 0
    replay: int = 0
    capability: int = 0
    destination: int = 0
    risk: int = 0
    context: int = 0
    approval: int = 0
    adapter_validation: int = 0

class CategoryMetrics(BaseModel):
    total_cases: int = 0
    passed: int = 0
    failed: int = 0
    detection_rate: float = 0.0
    prevention_rate: float = 0.0
    downstream_contact_count: int = 0

class MutationOperatorMetrics(BaseModel):
    total: int = 0
    passed: int = 0
    failed: int = 0
    pass_rate: float = 0.0

class MutationMetrics(BaseModel):
    total_mutations: int = 0
    passed_mutations: int = 0
    failed_mutations: int = 0
    mutation_pass_rate: float = 0.0
    operators: Dict[str, MutationOperatorMetrics] = {}

class ConfusionMatrix(BaseModel):
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    specificity: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0

class OperationsSummary(BaseModel):
    total_operations_evaluated: int = 0
    allowed_count: int = 0
    blocked_count: int = 0
    approval_required_count: int = 0
    allowed_by_operation: Dict[str, int] = {}
    blocked_by_operation: Dict[str, int] = {}
    approval_required_by_operation: Dict[str, int] = {}

class MetricsReport(BaseModel):
    total_cases: int
    passed_cases: int
    failed_cases: int
    attack_detection_rate: float
    attack_prevention_rate: float
    false_allow_rate: float
    false_block_rate: float
    downstream_contact_rate: float
    downstream_contacted: int
    downstream_not_contacted: int
    layer_metrics: LayerMetrics
    category_metrics: Dict[str, CategoryMetrics]
    mutation_metrics: MutationMetrics
    confusion_matrix: ConfusionMatrix = ConfusionMatrix()
    operations_summary: OperationsSummary = OperationsSummary()
    timestamp: Optional[str] = None

def calculate_metrics(
    attack_results: List[AttackRunResult], 
    mutation_results: List[MutationRunResult],
    timestamp: Optional[str] = None
) -> MetricsReport:
    total_cases = len(attack_results)
    
    if total_cases == 0:
        return MetricsReport(
            total_cases=0, passed_cases=0, failed_cases=0,
            attack_detection_rate=0.0, attack_prevention_rate=0.0,
            false_allow_rate=0.0, false_block_rate=0.0,
            downstream_contact_rate=0.0, downstream_contacted=0, downstream_not_contacted=0,
            layer_metrics=LayerMetrics(), category_metrics={},
            mutation_metrics=MutationMetrics(),
            confusion_matrix=ConfusionMatrix(),
            operations_summary=OperationsSummary(),
            timestamp=timestamp
        )
        
    passed_cases = sum(1 for r in attack_results if r.passed)
    failed_cases = total_cases - passed_cases
    
    attack_cases = [r for r in attack_results if r.category != "CONTROL"]
    control_cases = [r for r in attack_results if r.category == "CONTROL"]
    
    total_attack_cases = len(attack_cases)
    total_control_cases = len(control_cases)
    
    # Attack Detection Rate (percentage of attack cases flagged as BLOCK or REQUIRE_APPROVAL)
    blocked_attack_cases = sum(1 for r in attack_cases if r.observed_decision in ["BLOCK", "REQUIRE_APPROVAL"])
    attack_detection_rate = (blocked_attack_cases / total_attack_cases) * 100 if total_attack_cases > 0 else 0.0
    
    # Attack Prevention Rate (blocked and NO downstream contact)
    expected_to_be_blocked = sum(1 for r in attack_cases if r.expected_decision in ["BLOCK", "REQUIRE_APPROVAL"])
    prevented_attacks = sum(1 for r in attack_cases if r.observed_decision in ["BLOCK", "REQUIRE_APPROVAL"] and not r.observed_downstream_contact)
    attack_prevention_rate = (prevented_attacks / expected_to_be_blocked) * 100 if expected_to_be_blocked > 0 else 0.0
    
    # False Allow Rate (attacks erroneously allowed)
    incorrectly_allowed_attacks = sum(1 for r in attack_cases if r.observed_decision == "ALLOW" and r.expected_decision != "ALLOW")
    false_allow_rate = (incorrectly_allowed_attacks / total_attack_cases) * 100 if total_attack_cases > 0 else 0.0
    
    # False Block Rate (controls erroneously blocked)
    incorrectly_blocked_controls = sum(1 for r in control_cases if r.observed_decision != r.expected_decision)
    false_block_rate = (incorrectly_blocked_controls / total_control_cases) * 100 if total_control_cases > 0 else 0.0
    
    # Downstream Contact
    downstream_contacted = sum(1 for r in attack_results if r.observed_downstream_contact)
    downstream_not_contacted = total_cases - downstream_contacted
    downstream_contact_rate = (downstream_contacted / total_cases) * 100 if total_cases > 0 else 0.0
    
    # Layer Metrics
    layer_metrics = LayerMetrics()
    for r in attack_cases:
        if r.observed_decision in ["BLOCK", "REQUIRE_APPROVAL"] and not r.observed_downstream_contact:
            stage = r.observed_block_stage
            if stage and hasattr(layer_metrics, stage):
                setattr(layer_metrics, stage, getattr(layer_metrics, stage) + 1)
                
    # Category Metrics
    category_metrics = {}
    for cat in set(r.category for r in attack_results):
        cat_cases = [r for r in attack_results if r.category == cat]
        cat_total = len(cat_cases)
        cat_passed = sum(1 for r in cat_cases if r.passed)
        cat_downstream = sum(1 for r in cat_cases if r.observed_downstream_contact)
        
        if cat != "CONTROL":
            cat_blocked = sum(1 for r in cat_cases if r.observed_decision in ["BLOCK", "REQUIRE_APPROVAL"])
            cat_detection = (cat_blocked / cat_total) * 100 if cat_total > 0 else 0.0
            cat_exp_block = sum(1 for r in cat_cases if r.expected_decision in ["BLOCK", "REQUIRE_APPROVAL"])
            cat_prev = sum(1 for r in cat_cases if r.observed_decision in ["BLOCK", "REQUIRE_APPROVAL"] and not r.observed_downstream_contact)
            cat_prevention = (cat_prev / cat_exp_block) * 100 if cat_exp_block > 0 else 0.0
        else:
            cat_detection = 0.0
            cat_prevention = (cat_passed / cat_total) * 100 if cat_total > 0 else 0.0
            
        category_metrics[cat] = CategoryMetrics(
            total_cases=cat_total,
            passed=cat_passed,
            failed=cat_total - cat_passed,
            detection_rate=cat_detection,
            prevention_rate=cat_prevention,
            downstream_contact_count=cat_downstream
        )
        
    # Mutation Metrics
    total_mut = len(mutation_results)
    passed_mut = sum(1 for m in mutation_results if m.passed)
    failed_mut = total_mut - passed_mut
    mut_pass_rate = (passed_mut / total_mut) * 100 if total_mut > 0 else 0.0
    
    op_metrics = {}
    for m in mutation_results:
        op = m.operator
        if op not in op_metrics:
            op_metrics[op] = MutationOperatorMetrics()
        op_metrics[op].total += 1
        if m.passed:
            op_metrics[op].passed += 1
        else:
            op_metrics[op].failed += 1
            
    for op, m in op_metrics.items():
        m.pass_rate = (m.passed / m.total) * 100 if m.total > 0 else 0.0
        
    mutation_metrics = MutationMetrics(
        total_mutations=total_mut,
        passed_mutations=passed_mut,
        failed_mutations=failed_mut,
        mutation_pass_rate=mut_pass_rate,
        operators=op_metrics
    )

    # Confusion Matrix:
    # Positive class = Attack case (malicious request)
    # Negative class = Control case (benign request)
    # TP: Attack case correctly prevented without downstream contact
    tp = sum(1 for r in attack_cases if r.observed_decision in ["BLOCK", "REQUIRE_APPROVAL"] and not r.observed_downstream_contact)
    # FN: Attack case erroneously allowed or contacting downstream
    fn = sum(1 for r in attack_cases if r.observed_decision == "ALLOW" or r.observed_downstream_contact)
    # TN: Control case correctly handled (ALLOW -> 200/contact, or REQUIRE_APPROVAL)
    tn = sum(1 for r in control_cases if r.observed_decision == r.expected_decision and r.observed_downstream_contact == r.expected_downstream_contact)
    # FP: Control case erroneously blocked or failing expectation
    fp = sum(1 for r in control_cases if r.observed_decision != r.expected_decision or r.observed_downstream_contact != r.expected_downstream_contact)

    precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 100.0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 100.0
    specificity = (tn / (tn + fp)) * 100 if (tn + fp) > 0 else 100.0
    f1 = (2 * (precision * recall) / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = ((tp + tn) / (tp + tn + fp + fn)) * 100 if (tp + tn + fp + fn) > 0 else 0.0

    confusion_matrix = ConfusionMatrix(
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        precision=round(precision, 2),
        recall=round(recall, 2),
        specificity=round(specificity, 2),
        f1_score=round(f1, 2),
        accuracy=round(accuracy, 2)
    )

    # Operations Summary (Allowed vs Blocked breakdown)
    fixture_op_map = {f.fixture_id: f.target_capability for f in ATTACK_FIXTURES}
    allowed_by_op: Dict[str, int] = {}
    blocked_by_op: Dict[str, int] = {}
    appr_by_op: Dict[str, int] = {}

    for r in attack_results:
        op_name = fixture_op_map.get(r.fixture_id, r.name)
        if r.observed_decision == "ALLOW":
            allowed_by_op[op_name] = allowed_by_op.get(op_name, 0) + 1
        elif r.observed_decision == "REQUIRE_APPROVAL":
            appr_by_op[op_name] = appr_by_op.get(op_name, 0) + 1
        else: # BLOCK or ERROR
            blocked_by_op[op_name] = blocked_by_op.get(op_name, 0) + 1

    operations_summary = OperationsSummary(
        total_operations_evaluated=total_cases,
        allowed_count=sum(allowed_by_op.values()),
        blocked_count=sum(blocked_by_op.values()),
        approval_required_count=sum(appr_by_op.values()),
        allowed_by_operation=allowed_by_op,
        blocked_by_operation=blocked_by_op,
        approval_required_by_operation=appr_by_op
    )
    
    return MetricsReport(
        total_cases=total_cases,
        passed_cases=passed_cases,
        failed_cases=failed_cases,
        attack_detection_rate=attack_detection_rate,
        attack_prevention_rate=attack_prevention_rate,
        false_allow_rate=false_allow_rate,
        false_block_rate=false_block_rate,
        downstream_contact_rate=downstream_contact_rate,
        downstream_contacted=downstream_contacted,
        downstream_not_contacted=downstream_not_contacted,
        layer_metrics=layer_metrics,
        category_metrics=category_metrics,
        mutation_metrics=mutation_metrics,
        confusion_matrix=confusion_matrix,
        operations_summary=operations_summary,
        timestamp=timestamp
    )

def run_evaluation(export_path: Optional[str] = "evaluation_report.json") -> MetricsReport:
    """Runs actual evaluation via the configured runner modules and optionally exports results."""
    attack_results = run_all_fixtures()
    mutation_results = run_mutations()
    timestamp = datetime.now(timezone.utc).isoformat()
    report = calculate_metrics(attack_results, mutation_results, timestamp=timestamp)
    
    if export_path:
        try:
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(report.model_dump_json(indent=2))
        except Exception as e:
            print(f"[Warning] Could not export metrics to {export_path}: {e}")
            
    return report

def print_evaluation_report(report: MetricsReport):
    print("================================================================================")
    print("                    VETO SECURITY EVALUATION REPORT                             ")
    print("================================================================================")
    print(f"Total Test Cases:            {report.total_cases}")
    print(f"Passed Test Cases:           {report.passed_cases}")
    print(f"Failed Test Cases:           {report.failed_cases}")
    print(f"Attack Detection Rate:       {report.attack_detection_rate:.2f}%")
    print(f"Attack Prevention Rate:      {report.attack_prevention_rate:.2f}%")
    print(f"False Allow Rate:            {report.false_allow_rate:.2f}%")
    print(f"False Block Rate:            {report.false_block_rate:.2f}%")
    print(f"Downstream Contact Rate:     {report.downstream_contact_rate:.2f}%")
    
    cm = report.confusion_matrix
    print("\n--------------------------------------------------------------------------------")
    print("                            CONFUSION MATRIX                                    ")
    print("--------------------------------------------------------------------------------")
    print(f"  True Positives  (Attacks Correctly Blocked):        {cm.true_positives}")
    print(f"  True Negatives  (Controls Correctly Handled):       {cm.true_negatives}")
    print(f"  False Positives (Controls Erroneously Blocked):     {cm.false_positives}")
    print(f"  False Negatives (Attacks Erroneously Allowed):      {cm.false_negatives}")
    print(f"  Precision:      {cm.precision:.2f}%")
    print(f"  Recall:         {cm.recall:.2f}%")
    print(f"  Specificity:    {cm.specificity:.2f}%")
    print(f"  F1-Score:       {cm.f1_score:.2f}%")
    print(f"  Accuracy:       {cm.accuracy:.2f}%")

    ops = report.operations_summary
    print("\n--------------------------------------------------------------------------------")
    print("                      OPERATIONS DECISION BREAKDOWN                             ")
    print("--------------------------------------------------------------------------------")
    print(f"Total Operations:            {ops.total_operations_evaluated}")
    print(f"  Allowed:                   {ops.allowed_count}")
    for op, cnt in ops.allowed_by_operation.items():
        print(f"    - {op}: {cnt}")
    print(f"  Approval Required:         {ops.approval_required_count}")
    for op, cnt in ops.approval_required_by_operation.items():
        print(f"    - {op}: {cnt}")
    print(f"  Blocked:                   {ops.blocked_count}")
    for op, cnt in ops.blocked_by_operation.items():
        print(f"    - {op}: {cnt}")

    print("\n--------------------------------------------------------------------------------")
    print("                         LAYER-WISE ATTRIBUTION                                 ")
    print("--------------------------------------------------------------------------------")
    for layer, count in report.layer_metrics.model_dump().items():
        print(f"  {layer.capitalize():<22}: {count}")

    print("\n--------------------------------------------------------------------------------")
    print("                         MUTATION TESTING RESULTS                               ")
    print("--------------------------------------------------------------------------------")
    mut = report.mutation_metrics
    print(f"Total Mutations Generated:   {mut.total_mutations}")
    print(f"Passed Mutations:            {mut.passed_mutations}")
    print(f"Failed Mutations:            {mut.failed_mutations}")
    print(f"Mutation Pass Rate:          {mut.mutation_pass_rate:.2f}%")
    print("\nOperator Breakdown:")
    for op_name, op_m in sorted(mut.operators.items()):
        print(f"  {op_name:<28}: {op_m.passed}/{op_m.total} ({op_m.pass_rate:.1f}%)")
    print("================================================================================\n")

if __name__ == "__main__":
    report = run_evaluation()
    print_evaluation_report(report)
