import pytest
from attacks.fixtures import ATTACK_FIXTURES, AttackCategory, Severity
import os

def test_fixtures_unique_ids():
    ids = [f.fixture_id for f in ATTACK_FIXTURES]
    assert len(ids) == len(set(ids)), "Fixture IDs must be unique"

def test_fixtures_valid_schemas():
    for f in ATTACK_FIXTURES:
        assert isinstance(f.category, AttackCategory)
        assert isinstance(f.severity, Severity)
        assert f.expected_decision in ["ALLOW", "BLOCK", "REQUIRE_APPROVAL"]
        assert isinstance(f.expected_downstream_contact, bool)

def test_fixtures_block_stage():
    for f in ATTACK_FIXTURES:
        if f.expected_decision == "BLOCK":
            assert f.expected_block_stage != "none", f"Fixture {f.fixture_id} must have a block stage"
        elif f.expected_decision == "ALLOW":
            assert f.expected_block_stage == "none", f"Fixture {f.fixture_id} should not have a block stage"

def test_fixtures_downstream_contact():
    for f in ATTACK_FIXTURES:
        if f.expected_decision in ["BLOCK", "REQUIRE_APPROVAL"]:
            assert f.expected_downstream_contact is False, f"Fixture {f.fixture_id} should not contact downstream"
        elif f.expected_decision == "ALLOW":
            assert f.expected_downstream_contact is True, f"Fixture {f.fixture_id} should contact downstream"

def test_fixtures_no_secrets():
    # Check that known secrets are not in the payload strings
    # We shouldn't use real environment variables, but check literal common test strings
    for f in ATTACK_FIXTURES:
        payload_str = str(f.input_payload)
        assert "VETO_GMAIL_ACCESS_TOKEN" not in payload_str
        assert "VETO_PROVENANCE_SECRET" not in payload_str
        # Double check the test suite doesn't embed my real os environment variables
        for k, v in os.environ.items():
            if "SECRET" in k.upper() or "TOKEN" in k.upper():
                assert v not in payload_str

def test_fixtures_determinism():
    # Calling the registry again shouldn't change it
    from attacks.fixtures import ATTACK_FIXTURES as AF2
    assert len(ATTACK_FIXTURES) == len(AF2)
    for f1, f2 in zip(ATTACK_FIXTURES, AF2):
        assert f1.fixture_id == f2.fixture_id
        assert f1.input_payload == f2.input_payload

