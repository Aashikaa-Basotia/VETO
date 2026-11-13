from risk.destination import evaluate_destination

def test_trusted_destination():
    res = evaluate_destination("get_downstream_status")
    assert res.logical_name == "controlled_downstream"
    assert res.trust_level == "TRUSTED"
    assert "127.0.0.1" in res.endpoint_url

def test_unknown_destination_by_override():
    res = evaluate_destination("get_downstream_status", requested_destination="http://evil.com")
    assert res.logical_name == "http://evil.com"
    assert res.trust_level == "UNKNOWN"

def test_unknown_destination_by_unmapped_capability():
    res = evaluate_destination("unmapped_capability")
    assert res.logical_name == "unregistered"
    assert res.trust_level == "UNKNOWN"
