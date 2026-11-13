from risk.risk_evaluator import evaluate_risk

def test_evaluate_risk_low():
    res = evaluate_risk("get_downstream_status")
    assert res.risk_level == "LOW"

def test_evaluate_risk_medium():
    res = evaluate_risk("create_record")
    assert res.risk_level == "MEDIUM"
    
def test_evaluate_risk_high():
    res = evaluate_risk("delete_record")
    assert res.risk_level == "HIGH"

def test_evaluate_risk_unknown_defaults_high():
    res = evaluate_risk("unmapped_capability")
    assert res.risk_level == "HIGH"
