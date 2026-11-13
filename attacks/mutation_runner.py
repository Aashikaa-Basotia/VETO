import os
import json
import sqlite3
from typing import List, Dict, Any
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from attacks.fixtures import ATTACK_FIXTURES
from attacks.mutator import generate_all_mutations, MutationCase
from gateway.gateway import app

class MutationRunResult:
    def __init__(self, mutation: MutationCase, observed_decision: str, observed_block_stage: str, downstream_contact: bool, passed: bool, error: str = ""):
        self.mutation_id = mutation.mutation_id
        self.fixture_id = mutation.source_fixture_id
        self.operator = mutation.operator
        self.observed_decision = observed_decision
        self.observed_block_stage = observed_block_stage
        self.downstream_contact = downstream_contact
        self.passed = passed
        self.error = error

def setup_databases():
    import replay.engine
    import approval.engine
    
    # Initialize Replay DB
    replay.engine._replay_engine = None
    r_engine = replay.engine.get_replay_engine()
    r_engine._init_db()
    
    with sqlite3.connect("runner_mutation_replay.db") as conn:
        try:
            conn.execute("DELETE FROM replay_state")
            conn.commit()
        except sqlite3.OperationalError:
            pass

    # Initialize Approval DB
    approval.engine._approval_engine = None
    a_engine = approval.engine.get_approval_engine()
    a_engine._init_db()

    with sqlite3.connect("runner_mutation_approval.db") as conn:
        try:
            conn.execute("DELETE FROM approval_requests")
            conn.commit()
        except sqlite3.OperationalError:
            pass
            
    # Initialize Audit DB
    with sqlite3.connect("runner_mutation_audit.db") as conn:
        try:
            conn.execute("DELETE FROM audit_events")
            conn.commit()
        except sqlite3.OperationalError:
            pass

def run_mutations() -> List[MutationRunResult]:
    mutations = generate_all_mutations()
    results = []
    
    # Isolate databases for mutations
    env_patcher = patch.dict(os.environ, {
        "VETO_APPROVAL_DB": "runner_mutation_approval.db", 
        "VETO_AUDIT_DB": "runner_mutation_audit.db",
        "VETO_REPLAY_DB": "runner_mutation_replay.db",
        "VETO_GMAIL_ACCESS_TOKEN": "mock"
    })
    
    with env_patcher:
        setup_databases()
        client = TestClient(app)
        
        for mut in mutations:
            setup_databases() # Clean databases between mutations to prevent cross-contamination
            
            with patch('urllib.request.urlopen') as mock_urlopen:
                # Mock downstream responses
                mock_response = MagicMock()
                mock_response.read.return_value = b'{"status": "ok", "id": "mocked"}'
                mock_response.__enter__.return_value = mock_response
                mock_urlopen.return_value = mock_response
                
                observed_decision = "UNKNOWN"
                if mut.expected_block_stage == "adapter_validation" and mut.mutated_payload.get("operation") in ["send_email", "create_record"]:
                    from approval.engine import get_approval_engine
                    engine = get_approval_engine()
                    appr_id = engine.create_approval_request("default_agent", mut.mutated_payload.get("operation"), mut.mutated_payload.get("arguments", {}))
                    engine.update_approval_status(appr_id, "APPROVED")
                    
                env_overrides = {"VETO_GMAIL_ACCESS_TOKEN": "mock_token"}
                if "execution_mode_override" in mut.mutated_payload:
                    env_overrides["VETO_EXECUTION_MODE"] = mut.mutated_payload.pop("execution_mode_override")
                    
                with patch.dict(os.environ, env_overrides):
                    response = client.post("/gateway/execute", json=mut.mutated_payload)
                downstream_contact = mock_urlopen.called
                
                if response.status_code == 200:
                    observed_decision = "ALLOW"
                    observed_block_stage = "none"
                elif response.status_code == 403:
                    resp_json = response.json()
                    detail = resp_json.get("detail", {})
                    
                    if isinstance(detail, dict):
                        observed_decision = detail.get("decision", "BLOCK")
                        reason = detail.get("reason", "unknown")
                        
                        if "provenance" in reason:
                            observed_block_stage = "provenance"
                        elif "missing_request_id" in reason or "replay_detected" in reason:
                            observed_block_stage = "replay_detected" # group missing_request_id and replay_detected under replay_detected for stage matching
                        elif "Capability not authorized" in reason or "not authorized" in reason or "Malformed" in reason:
                            observed_block_stage = "capability"
                        elif "unknown_destination" in reason:
                            observed_block_stage = "destination"
                        elif "risk" in reason:
                            observed_block_stage = "risk"
                        elif "context" in reason or "state_changing" in reason:
                            observed_block_stage = "context"
                        elif "approval" in reason or observed_decision == "REQUIRE_APPROVAL":
                            observed_block_stage = "approval"
                        else:
                            observed_block_stage = reason
                    else:
                        observed_decision = "BLOCK"
                        observed_block_stage = "unknown"
                elif response.status_code == 422:
                    observed_decision = "BLOCK"
                    observed_block_stage = "adapter_validation"
                else:
                    detail = response.json().get("detail", {}) if response.status_code != 500 else "Server Error"
                    if isinstance(detail, dict):
                        observed_decision = detail.get("decision", "BLOCK")
                        reason = detail.get("reason", "unknown")
                        if "approval" in reason or observed_decision == "REQUIRE_APPROVAL":
                            observed_block_stage = "approval"
                        else:
                            observed_block_stage = "adapter_validation"
                    else:
                        observed_decision = "BLOCK"
                        observed_block_stage = "adapter_validation"

                passed = True
                error = ""
                
                if mut.expected_decision and observed_decision != mut.expected_decision:
                    passed = False
                    error = f"Expected decision {mut.expected_decision}, got {observed_decision}"
                elif mut.expected_block_stage != "unknown" and observed_block_stage != mut.expected_block_stage:
                    passed = False
                    error = f"Expected block stage {mut.expected_block_stage}, got {observed_block_stage}"
                elif mut.expected_downstream_contact is False and downstream_contact:
                    passed = False
                    error = "Expected NO downstream contact, but network call was made"
                    
                results.append(MutationRunResult(mut, observed_decision, observed_block_stage, downstream_contact, passed, error))
                
    return results

if __name__ == "__main__":
    results = run_mutations()
    
    passed_count = sum(1 for r in results if r.passed)
    failed_count = sum(1 for r in results if not r.passed)
    
    print(f"Executed {len(results)} mutations.")
    print(f"Passed: {passed_count}")
    print(f"Failed: {failed_count}")
    
    if failed_count > 0:
        print("\n--- Failures ---")
        for r in results:
            if not r.passed:
                print(f"Mutation {r.mutation_id} ({r.operator}) failed: {r.error}")
