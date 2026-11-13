import pytest
from attacks.mutator import generate_all_mutations, MUTATION_OPERATORS, make_mutation
from attacks.fixtures import AttackFixture, AttackCategory

def test_mutation_registry_validation():
    mutations = generate_all_mutations()
    assert len(mutations) > 0
    assert len(MUTATION_OPERATORS) >= 12
    operators_seen = set([m.operator for m in mutations])
    assert "EMPTY_VALUE" in operators_seen
    assert "TYPE_CONFUSION" in operators_seen

def test_mutation_stable_ids():
    mutations = generate_all_mutations()
    # IDs should be deterministic and stable
    ids = [m.mutation_id for m in mutations]
    assert len(ids) == len(set(ids)), "Mutation IDs must be unique"
    for m in mutations:
        assert m.mutation_id.startswith(f"MUT-{m.source_fixture_id}-{m.operator}-")

def test_mutation_no_secret_leakage():
    mutations = generate_all_mutations()
    for m in mutations:
        payload_str = str(m.mutated_payload)
        assert "default-dev-secret-12345" not in payload_str, "Secret must not leak in mutation payloads"

def test_mutation_repeatability():
    mutations_1 = generate_all_mutations()
    mutations_2 = generate_all_mutations()
    assert len(mutations_1) == len(mutations_2)
    for m1, m2 in zip(mutations_1, mutations_2):
        assert m1.mutation_id == m2.mutation_id
        assert m1.mutated_payload == m2.mutated_payload
        assert m1.expected_decision == m2.expected_decision

def test_mutation_does_not_alter_base_fixtures():
    from attacks.fixtures import ATTACK_FIXTURES
    # Snapshot before
    import copy
    snapshot = copy.deepcopy(ATTACK_FIXTURES)
    
    generate_all_mutations()
    
    # Check after
    for f_orig, f_after in zip(snapshot, ATTACK_FIXTURES):
        assert f_orig.input_payload == f_after.input_payload

def test_mutation_downstream_isolation():
    # Downstream should be tested in mutation_runner but we can verify expected boolean
    mutations = generate_all_mutations()
    for m in mutations:
        if m.expected_decision == "BLOCK":
            assert m.expected_downstream_contact is False
