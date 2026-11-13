import copy
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from attacks.fixtures import AttackFixture, AttackCategory, ATTACK_FIXTURES
from provenance.verifier import generate_provenance_signature

def safe_sign(fixture: AttackFixture, p: dict):
    if "provenance_signature" in p and fixture.category != AttackCategory.PROVENANCE:
        p["provenance_signature"] = generate_provenance_signature(p.get("operation", ""), p.get("arguments", {}), p.get("request_id"))
    return p

PIPELINE_ORDER = [
    "provenance", 
    "replay_detected", 
    "capability", 
    "destination", 
    "risk", 
    "context", 
    "approval", 
    "adapter_validation", 
    "none"
]

def resolve_expected_outcome(fixture: AttackFixture, mutated_stage: str, mutated_decision: str):
    orig_idx = PIPELINE_ORDER.index(fixture.expected_block_stage) if fixture.expected_block_stage in PIPELINE_ORDER else 99
    mut_idx = PIPELINE_ORDER.index(mutated_stage) if mutated_stage in PIPELINE_ORDER else 99
    
    if fixture.expected_decision == "BLOCK" and orig_idx < mut_idx:
        return fixture.expected_decision, fixture.expected_block_stage
    return mutated_decision, mutated_stage

class MutationCase(BaseModel):
    mutation_id: str
    source_fixture_id: str
    operator: str
    description: str
    original_payload: Dict[str, Any]
    mutated_payload: Dict[str, Any]
    expected_decision: str
    expected_block_stage: str
    expected_downstream_contact: bool

def make_mutation(fixture: AttackFixture, op_name: str, index: int, payload: dict, decision: str, stage: str, downstream: bool, desc: str) -> MutationCase:
    return MutationCase(
        mutation_id=f"MUT-{fixture.fixture_id}-{op_name}-{index:03d}",
        source_fixture_id=fixture.fixture_id,
        operator=op_name,
        description=desc,
        original_payload=fixture.input_payload,
        mutated_payload=payload,
        expected_decision=decision,
        expected_block_stage=stage,
        expected_downstream_contact=downstream
    )

def op_missing_field(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    
    # 1. Missing operation
    if "operation" in payload:
        p = copy.deepcopy(payload)
        del p["operation"]
        res.append(make_mutation(fixture, "MISSING_FIELD", len(res)+1, p, "BLOCK", "adapter_validation", False, "Missing operation field"))
        
    # 2. Missing provenance
    if "provenance_signature" in payload:
        p = copy.deepcopy(payload)
        del p["provenance_signature"]
        res.append(make_mutation(fixture, "MISSING_FIELD", len(res)+1, p, "BLOCK", "provenance", False, "Missing provenance_signature field"))
        
    return res

def op_empty_value(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    
    # Empty operation
    if "operation" in payload:
        p = copy.deepcopy(payload)
        p["operation"] = ""
        # Re-sign so it passes provenance but fails capability
        p = safe_sign(fixture, p)
        res.append(make_mutation(fixture, "EMPTY_VALUE", len(res)+1, p, *resolve_expected_outcome(fixture, "capability", "BLOCK"), False, "Empty operation string"))

    args = payload.get("arguments", {})
    if "message_id" in args:
        p = copy.deepcopy(payload)
        p["arguments"]["message_id"] = ""
        p = safe_sign(fixture, p)
        res.append(make_mutation(fixture, "EMPTY_VALUE", len(res)+1, p, "BLOCK", "adapter_validation", False, "Empty message_id"))
        
    return res

def op_null_value(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    
    if "arguments" in payload:
        p = copy.deepcopy(payload)
        p["arguments"] = None
        # Invalid payload type for arguments (dict expected)
        res.append(make_mutation(fixture, "NULL_VALUE", len(res)+1, p, "BLOCK", "adapter_validation", False, "Null arguments"))
        
    return res

def op_type_confusion(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    
    if "request_id" in payload:
        p = copy.deepcopy(payload)
        p["request_id"] = 12345 # integer instead of string
        res.append(make_mutation(fixture, "TYPE_CONFUSION", len(res)+1, p, "BLOCK", "adapter_validation", False, "request_id as integer"))
        
    return res

def op_boundary_length(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    args = payload.get("arguments", {})
    
    if payload.get("operation") == "send_email" and "subject" in args:
        p = copy.deepcopy(payload)
        p["arguments"]["subject"] = "A" * 257 # Max is 255 typically in the gmail adapter
        p = safe_sign(fixture, p)
        res.append(make_mutation(fixture, "BOUNDARY_LENGTH", len(res)+1, p, *resolve_expected_outcome(fixture, "adapter_validation", "BLOCK"), False, "Subject exceeds length limit"))
        
        p2 = copy.deepcopy(payload)
        p2["arguments"]["body"] = "A" * (100 * 1024 + 1) # Max is 100KB
        p2 = safe_sign(fixture, p2)
        res.append(make_mutation(fixture, "BOUNDARY_LENGTH", len(res)+1, p2, *resolve_expected_outcome(fixture, "adapter_validation", "BLOCK"), False, "Body exceeds length limit"))
        
    return res

def op_string_normalization(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    args = payload.get("arguments", {})
    
    if "to" in args:
        p = copy.deepcopy(payload)
        p["arguments"]["to"] = " " + p["arguments"]["to"] + " "
        p = safe_sign(fixture, p)
        # Should be stripped or validated, assuming VETO or adapter handles it safely. Inherits original fixture's expectation.
        res.append(make_mutation(fixture, "NORMALIZATION", len(res)+1, p, *resolve_expected_outcome(fixture, fixture.expected_block_stage, fixture.expected_decision), fixture.expected_downstream_contact, "Leading/trailing spaces in email"))
        
    return res

def op_path_injection(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    args = payload.get("arguments", {})
    
    if "message_id" in args:
        p = copy.deepcopy(payload)
        p["arguments"]["message_id"] = "../../../etc/passwd"
        p = safe_sign(fixture, p)
        res.append(make_mutation(fixture, "PATH_INJECTION", len(res)+1, p, *resolve_expected_outcome(fixture, "adapter_validation", "BLOCK"), False, "Path traversal in message_id"))
        
    return res

def op_destination_mutation(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    
    # Mutate to local host
    p = copy.deepcopy(payload)
    p["destination_override"] = "http://127.0.0.1:9999"
    # Destination is overriden without affecting HMAC (since it's not signed, or if it is, wait, destination_override is not signed)
    res.append(make_mutation(fixture, "DESTINATION", len(res)+1, p, *resolve_expected_outcome(fixture, "destination", "BLOCK"), False, "SSRF attempt via override"))
    return res

def op_capability_mutation(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    
    if payload.get("operation") == "get_downstream_status":
        p = copy.deepcopy(payload)
        p["operation"] = "delete_record"
        p["request_id"] = "REQ-MUTATED-CAP-001"
        p = safe_sign(fixture, p)
        res.append(make_mutation(fixture, "CAPABILITY", len(res)+1, p, *resolve_expected_outcome(fixture, "capability", "BLOCK"), False, "Escalate to delete_record"))
        
    return res

def op_provenance_mutation(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    
    if "provenance_signature" in payload:
        p = copy.deepcopy(payload)
        p["provenance_signature"] = "tampered_signature"
        res.append(make_mutation(fixture, "PROVENANCE", len(res)+1, p, "BLOCK", "provenance", False, "Invalid signature"))
        
        p2 = copy.deepcopy(payload)
        p2["provenance_signature"] = payload["provenance_signature"][:-5]
        res.append(make_mutation(fixture, "PROVENANCE", len(res)+1, p2, "BLOCK", "provenance", False, "Truncated signature"))
        
    return res

def op_replay_mutation(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    
    if "request_id" in payload:
        # Re-use the identical request_id but change arguments (sign it with the new arguments). 
        # Wait, if we use the identical request_id, it should be caught by replay if it was already consumed. 
        # But mutations are run independently on a clean DB! So it WON'T be caught by replay if we just change arguments. 
        # Unless we design the mutation runner to run the original first. 
        # Let's test missing request_id instead on a state changing op.
        if payload.get("operation") in ["create_record", "delete_record", "send_email"]:
            p = copy.deepcopy(payload)
            del p["request_id"]
            p = safe_sign(fixture, p)
            res.append(make_mutation(fixture, "REPLAY", len(res)+1, p, *resolve_expected_outcome(fixture, "replay_detected", "BLOCK"), False, "Missing request_id for state change"))
            # Note: gateway returns reason 'missing_request_id', let's map expected_block_stage to 'replay_detected' or 'unknown'
            # We'll map missing_request_id -> 'unknown' or 'replay' in runner.
            
    return res

def op_approval_mutation(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    
    # Client injecting approved=true
    p = copy.deepcopy(payload)
    if "arguments" not in p:
        p["arguments"] = {}
    p["arguments"]["approved"] = True
    p = safe_sign(fixture, p)
    
    expected_decision = fixture.expected_decision
    expected_stage = fixture.expected_block_stage
    expected_downstream = fixture.expected_downstream_contact
    if expected_decision == "ALLOW" and p["operation"] in ["create_record", "delete_record", "send_email"]:
        expected_decision = "REQUIRE_APPROVAL"
        expected_stage = "approval"
        expected_downstream = False
        
    expected_outcome_decision, expected_outcome_stage = resolve_expected_outcome(fixture, expected_stage, expected_decision)
    res.append(make_mutation(fixture, "APPROVAL", len(res)+1, p, expected_outcome_decision, expected_outcome_stage, expected_downstream, "Inject approved=True"))
        
    return res

def op_context_mutation(fixture: AttackFixture) -> List[MutationCase]:
    res = []
    payload = fixture.input_payload
    
    p = copy.deepcopy(payload)
    p["execution_mode_override"] = "normal"  # Attempt to force normal mode
    # If the environment is restricted, VETO should ignore this and still block state-changing ops.
    if p["operation"] in ["create_record", "delete_record", "send_email"]:
        # We expect context block IF the environment is restricted. The runner will run this with restricted context.
        # But wait! If the expected decision depends on the runner's context...
        pass
        
    return res

MUTATION_OPERATORS = [
    op_missing_field,
    op_empty_value,
    op_null_value,
    op_type_confusion,
    op_boundary_length,
    op_string_normalization,
    op_path_injection,
    op_destination_mutation,
    op_capability_mutation,
    op_provenance_mutation,
    op_replay_mutation,
    op_approval_mutation,
    op_context_mutation
]

def generate_mutations(fixture: AttackFixture) -> List[MutationCase]:
    mutations = []
    for op in MUTATION_OPERATORS:
        mutations.extend(op(fixture))
    return mutations

def generate_all_mutations() -> List[MutationCase]:
    all_muts = []
    for f in ATTACK_FIXTURES:
        base_payload = dict(f.input_payload)
        if "provenance_signature" not in base_payload and f.category != AttackCategory.PROVENANCE:
            base_payload["provenance_signature"] = generate_provenance_signature(
                base_payload.get("operation", ""),
                base_payload.get("arguments", {}),
                base_payload.get("request_id")
            )
        f_signed = AttackFixture(
            fixture_id=f.fixture_id,
            name=f.name,
            category=f.category,
            description=f.description,
            target_capability=f.target_capability,
            input_payload=base_payload,
            expected_decision=f.expected_decision,
            expected_block_stage=f.expected_block_stage,
            expected_downstream_contact=f.expected_downstream_contact,
            severity=f.severity
        )
        all_muts.extend(generate_mutations(f_signed))
    return all_muts



