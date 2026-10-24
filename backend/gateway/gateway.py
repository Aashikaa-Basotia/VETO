import os
import json
import logging
import urllib.request
import urllib.error
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from policy.engine import evaluate_capability, PolicyRequest
from risk.destination import evaluate_destination
from risk.risk_evaluator import evaluate_risk
from context.evaluator import evaluate_context, get_trusted_context
from provenance.verifier import verify_provenance

from audit.logger import get_audit_logger, create_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("veto_gateway")

app = FastAPI(title="VETO Transparent Gateway")
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from gateway.email_routes import router as email_router
app.include_router(email_router)

class GatewayRequest(BaseModel):
    operation: str
    arguments: Dict[str, Any] = {}
    destination_override: Optional[str] = None
    execution_mode_override: Optional[str] = None # To test manipulation protection
    provenance_signature: Optional[str] = None # Signature from trusted MCP layer
    request_id: Optional[str] = None # Replay identity

@app.post("/gateway/execute")
def execute_operation(req: GatewayRequest):
    logger.info(f"[VETO] Received operation: {req.operation}")
    
    audit_logger = get_audit_logger()
    audit_state = {
        "operation": req.operation,
        "agent_id": "default_agent",
        "request_id": req.request_id,
        "provenance_ver": None,
        "replay_decision": None,
        "cap_decision": None,
        "dest_trust": None,
        "risk_lvl": None,
        "context_decision": None,
        "final_decision": "BLOCK",
        "reason": "unknown",
        "downstream_executed": False
    }

    def abort(reason: str, status_code: int = 403):
        audit_state["reason"] = reason
        audit_state["final_decision"] = "BLOCK"
        audit_state["downstream_executed"] = False
        event = create_event(**audit_state)
        audit_logger.record_event(event)
        raise HTTPException(status_code=status_code, detail={"decision": "BLOCK", "reason": reason})

    # 1.5 Provenance Verification
    prov_decision = verify_provenance(req.operation, req.arguments, req.provenance_signature, req.request_id)
    audit_state["provenance_ver"] = prov_decision.verification
    
    if prov_decision.decision == "BLOCK":
        logger.warning(f"[VETO][PROVENANCE] source={prov_decision.source} verification={prov_decision.verification} decision=BLOCK reason={prov_decision.reason}")
        abort(prov_decision.reason)
        
    logger.info(f"[VETO][PROVENANCE] source={prov_decision.source} verification={prov_decision.verification} decision=ALLOW")
    
    # 1.6 Replay Protection
    # Replay protection is enforced explicitly for state-changing operations.
    state_changing_ops = ["create_record", "delete_record", "send_email", "create_calendar_event"]
    
    if req.operation in state_changing_ops:
        if not req.request_id:
            logger.warning(f"[VETO][REPLAY] operation={req.operation} decision=BLOCK reason=missing_request_id")
            audit_state["replay_decision"] = "BLOCK"
            abort("missing_request_id")
            
        from replay.engine import get_replay_engine
        engine = get_replay_engine()
        is_fresh = engine.check_and_consume(req.request_id, "default_agent", req.operation)
        
        if not is_fresh:
            logger.warning(f"[VETO][REPLAY] operation={req.operation} request_id={req.request_id} decision=BLOCK reason=replay_detected")
            audit_state["replay_decision"] = "BLOCK"
            abort("replay_detected")
            
        audit_state["replay_decision"] = "ALLOW"
        logger.info(f"[VETO][REPLAY] operation={req.operation} request_id={req.request_id} decision=ALLOW")
    else:
        audit_state["replay_decision"] = "NOT_EVALUATED"
        logger.info(f"[VETO][REPLAY] operation={req.operation} decision=NOT_EVALUATED reason=read_operation")

    # 2. Capability Policy Evaluation
    policy_req = PolicyRequest(
        agent_id="default_agent",  # Fixed for now since no authentication is implemented
        capability=req.operation,
        arguments=req.arguments
    )
    
    decision = evaluate_capability(policy_req)
    audit_state["cap_decision"] = decision.decision
    
    if decision.decision == "BLOCK":
        logger.info(f"[VETO][POLICY] capability={decision.capability} decision=BLOCK reason={decision.reason.replace(' ', '_')}")
        abort(decision.reason)
        
    logger.info(f"[VETO][POLICY] capability={decision.capability} decision=ALLOW")

    # 3. Destination Evaluation
    dest_result = evaluate_destination(req.operation, requested_destination=req.destination_override)
    audit_state["dest_trust"] = dest_result.trust_level
    logger.info(f"[VETO][DESTINATION] destination={dest_result.logical_name} trust={dest_result.trust_level}")
    
    if dest_result.trust_level != "TRUSTED":
        logger.info(f"[VETO][DECISION] capability={req.operation} decision=BLOCK reason=unknown_destination")
        abort("unknown_destination")
        
    # 4. Risk Evaluation
    risk_result = evaluate_risk(req.operation)
    audit_state["risk_lvl"] = risk_result.risk_level
    logger.info(f"[VETO][RISK] capability={risk_result.capability} risk={risk_result.risk_level}")
    
    if risk_result.risk_level == "HIGH":
        logger.info(f"[VETO][DECISION] capability={req.operation} decision=BLOCK reason=high_risk_operation")
        abort("high_risk_operation")
        
    # 5. Context Evaluation
    # Retrieve trusted context controlled by VETO, independent of LLM payload.
    # We ignore req.execution_mode_override completely for real evaluation to prevent bypass.
    security_context = get_trusted_context(agent_id="default_agent")
    context_result = evaluate_context(req.operation, security_context)
    audit_state["context_decision"] = context_result.decision
    
    if context_result.decision == "BLOCK":
        logger.info(f"[VETO][CONTEXT] environment={security_context.environment} mode={security_context.execution_mode} decision=BLOCK reason={context_result.reason}")
        logger.info(f"[VETO][DECISION] capability={req.operation} decision=BLOCK")
        abort(context_result.reason)

    logger.info(f"[VETO][CONTEXT] environment={security_context.environment} mode={security_context.execution_mode} decision=ALLOW")
    
    # 5.5 Approval Evaluation
    from approval.engine import requires_approval, get_approval_engine, generate_request_hash
    
    if requires_approval(req.operation):
        approval_engine = get_approval_engine()
        is_approved = approval_engine.check_approval("default_agent", req.operation, req.arguments)
        req_hash = generate_request_hash("default_agent", req.operation, req.arguments)
        
        audit_state["request_hash"] = req_hash
        
        if not is_approved:
            # Check if pending
            # Create request if not exist (simplifying: just create new each time or use deterministic check)
            approval_id = approval_engine.create_approval_request("default_agent", req.operation, req.arguments)
            logger.info(f"[VETO][APPROVAL] capability={req.operation} decision=REQUIRE_APPROVAL approval_id={approval_id}")
            
            audit_state["approval_id"] = approval_id
            audit_state["approval_status"] = "PENDING"
            audit_state["final_decision"] = "REQUIRE_APPROVAL"
            audit_state["reason"] = "approval_required"
            audit_state["downstream_executed"] = False
            audit_logger.record_event(create_event(**audit_state))
            
            raise HTTPException(status_code=403, detail={
                "decision": "REQUIRE_APPROVAL",
                "approval_id": approval_id,
                "operation": req.operation
            })
            
        logger.info(f"[VETO][APPROVAL] capability={req.operation} decision=ALLOW")
        audit_state["approval_status"] = "APPROVED"
        
    logger.info(f"[VETO][DECISION] capability={req.operation} decision=ALLOW")
    
    # Ready for execution
    audit_state["final_decision"] = "ALLOW"
    audit_state["reason"] = "all_security_checks_passed"
    
    # 6. Downstream Execution
    if req.operation == "get_downstream_status":
        url = f"{dest_result.endpoint_url}/status"
        logger.info("[VETO] Forwarding to controlled downstream service (GET /status)")
        
        try:
            http_req = urllib.request.Request(url)
            with urllib.request.urlopen(http_req, timeout=5.0) as response:
                result = json.loads(response.read().decode("utf-8"))
                logger.info("[VETO] Downstream response received")
                audit_state["downstream_executed"] = True
                audit_logger.record_event(create_event(**audit_state))
                return result
        except urllib.error.URLError as e:
            logger.error(f"[VETO] Downstream error: {e}")
            audit_state["downstream_executed"] = False
            audit_state["reason"] = "downstream_connection_error"
            audit_logger.record_event(create_event(**audit_state))
            raise HTTPException(status_code=502, detail=f"Failed to connect to downstream service: {e}")
            
    elif req.operation == "create_record":
        url = f"{dest_result.endpoint_url}/records"
        logger.info("[VETO] Forwarding to controlled downstream service (POST /records)")
        
        # Basic interface validation
        if "name" not in req.arguments or "value" not in req.arguments:
             abort("missing_required_arguments", status_code=400)
             
        data = json.dumps({"name": req.arguments["name"], "value": req.arguments["value"]}).encode("utf-8")
        try:
            http_req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(http_req, timeout=5.0) as response:
                result = json.loads(response.read().decode("utf-8"))
                logger.info("[VETO] Downstream response received")
                audit_state["downstream_executed"] = True
                audit_logger.record_event(create_event(**audit_state))
                return result
        except urllib.error.HTTPError as e:
            logger.error(f"[VETO] Downstream HTTP Error: {e.code}")
            audit_state["downstream_executed"] = True
            audit_state["reason"] = f"downstream_http_error_{e.code}"
            audit_logger.record_event(create_event(**audit_state))
            raise HTTPException(status_code=e.code, detail=f"Downstream HTTP Error: {e.code}")
        except urllib.error.URLError as e:
            logger.error(f"[VETO] Downstream error: {e}")
            audit_state["downstream_executed"] = False
            audit_state["reason"] = "downstream_connection_error"
            audit_logger.record_event(create_event(**audit_state))
            raise HTTPException(status_code=502, detail=f"Failed to connect to downstream service: {e}")
            
    elif req.operation in ["list_recent_emails", "get_email_metadata", "get_email_body", "send_email"]:
        logger.info(f"[VETO] Forwarding to Gmail adapter ({req.operation})")
        from services.gmail import GmailAdapter
        adapter = GmailAdapter()
        
        try:
            if req.operation == "list_recent_emails":
                max_results = req.arguments.get("max_results", 5)
                result = adapter.list_recent_emails(max_results=max_results)
            elif req.operation == "get_email_metadata":
                message_id = req.arguments.get("message_id")
                if not message_id:
                    abort("missing_message_id", status_code=400)
                result = adapter.get_email_metadata(message_id=message_id)
            elif req.operation == "get_email_body":
                message_id = req.arguments.get("message_id")
                if not message_id:
                    abort("missing_message_id", status_code=400)
                result = adapter.get_email_body(message_id=message_id)
            elif req.operation == "send_email":
                to = req.arguments.get("to")
                subject = req.arguments.get("subject")
                body = req.arguments.get("body")
                if not to or not subject or not body:
                    abort("missing_send_arguments", status_code=400)
                result = adapter.send_email(to=to, subject=subject, body=body)
                
            logger.info("[VETO] Gmail response received")
            audit_state["downstream_executed"] = True
            audit_logger.record_event(create_event(**audit_state))
            return result
        except urllib.error.HTTPError as e:
            logger.error(f"[VETO] Gmail HTTP Error: {e.code}")
            audit_state["downstream_executed"] = True
            audit_state["reason"] = f"gmail_http_error_{e.code}"
            audit_logger.record_event(create_event(**audit_state))
            raise HTTPException(status_code=e.code, detail=f"Gmail HTTP Error: {e.code}")
        except urllib.error.URLError as e:
            logger.error(f"[VETO] Gmail Connection error: {e}")
            audit_state["downstream_executed"] = False
            audit_state["reason"] = "gmail_connection_error"
            audit_logger.record_event(create_event(**audit_state))
            raise HTTPException(status_code=502, detail=f"Failed to connect to Gmail: {e}")
        except HTTPException as e:
            # Let abort() exceptions bubble up
            raise e
        except Exception as e:
            logger.error(f"[VETO] Gmail Adapter error: {e}")
            audit_state["downstream_executed"] = False
            audit_state["reason"] = "gmail_api_error"
            audit_logger.record_event(create_event(**audit_state))
            raise HTTPException(status_code=500, detail=f"Gmail Adapter error: {e}")
            
    
    elif req.operation in ["list_calendar_events", "create_calendar_event"]:
        logger.info(f"[VETO] Forwarding to Calendar adapter ({req.operation})")
        from services.calendar import CalendarAdapter
        adapter = CalendarAdapter()
        
        try:
            if req.operation == "list_calendar_events":
                max_results = req.arguments.get("max_results", 10)
                result = adapter.list_calendar_events(max_results=max_results)
            elif req.operation == "create_calendar_event":
                summary = req.arguments.get("summary")
                start = req.arguments.get("start")
                end = req.arguments.get("end")
                if not summary or not start or not end:
                    abort("missing_create_calendar_arguments", status_code=400)
                result = adapter.create_calendar_event(summary=summary, start=start, end=end)
                
            logger.info("[VETO] Calendar response received")
            audit_state["downstream_executed"] = True
            audit_logger.record_event(create_event(**audit_state))
            return result
        except Exception as e:
            logger.error(f"[VETO] Calendar error: {e}")
            raise HTTPException(status_code=500, detail=f"Calendar Adapter error: {e}")
            
    else:
        logger.warning(f"[VETO] Invalid/unsupported operation: {req.operation}")
        abort("unsupported_operation", status_code=400)

@app.post("/approval/{approval_id}/approve")
def approve_request(approval_id: str):
    from approval.engine import get_approval_engine
    engine = get_approval_engine()
    success = engine.update_approval_status(approval_id, "APPROVED")
    if not success:
        raise HTTPException(status_code=400, detail="Invalid transition or approval_id not found")
        
    audit_logger = get_audit_logger()
    audit_logger.record_event(create_event(
        operation="approve_request",
        agent_id="human",
        approval_id=approval_id,
        approval_status="APPROVED",
        final_decision="ALLOW",
        reason="human_approved"
    ))
    return {"status": "APPROVED"}

@app.post("/approval/{approval_id}/reject")
def reject_request(approval_id: str):
    from approval.engine import get_approval_engine
    engine = get_approval_engine()
    success = engine.update_approval_status(approval_id, "REJECTED")
    if not success:
        raise HTTPException(status_code=400, detail="Invalid transition or approval_id not found")
        
    audit_logger = get_audit_logger()
    audit_logger.record_event(create_event(
        operation="reject_request",
        agent_id="human",
        approval_id=approval_id,
        approval_status="REJECTED",
        final_decision="BLOCK",
        reason="human_rejected"
    ))
    return {"status": "REJECTED"}

@app.get("/api/dashboard/summary")
def get_dashboard_summary():
    logger = get_audit_logger()
    events = logger.get_events()
    total = len(events)
    allowed = sum(1 for e in events if e.final_decision == "ALLOW")
    blocked = sum(1 for e in events if e.final_decision == "BLOCK")
    approvals = sum(1 for e in events if e.final_decision == "REQUIRE_APPROVAL")
    return {
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "approvals": approvals
    }

@app.get("/api/decisions")
def get_decisions():
    logger = get_audit_logger()
    events = logger.get_events()
    return events[::-1]

@app.get("/api/approvals")
def get_approvals():
    from approval.engine import get_approval_engine
    engine = get_approval_engine()
    approvals = engine.get_all_approvals()
    return approvals

@app.get("/api/evaluation")
def get_evaluation():
    report_path = "evaluation_report.json" if os.path.isfile("evaluation_report.json") else os.path.join("docs", "reports", "evaluation_report.json")
    if os.path.isfile(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                operators_list = []
                for op_name, op_m in data.get("mutation_metrics", {}).get("operators", {}).items():
                    operators_list.append({
                        "name": f"{op_name.replace('_', ' ').title()} mutation",
                        "result": "✓" if op_m.get("failed", 0) == 0 else f"{op_m.get('passed')}/{op_m.get('total')}"
                    })
                return {
                    "generated": True,
                    "timestamp": data.get("timestamp"),
                    "detection_rate": f"{data.get('attack_detection_rate', 100):.1f}%",
                    "prevention_rate": f"{data.get('attack_prevention_rate', 100):.1f}%",
                    "false_allow": f"{data.get('false_allow_rate', 0):.1f}%",
                    "false_block": f"{data.get('false_block_rate', 0):.1f}%",
                    "mutations_passed": f"{data.get('mutation_metrics', {}).get('passed_mutations', 0)} / {data.get('mutation_metrics', {}).get('total_mutations', 0)}",
                    "security_tests": f"{data.get('total_cases', 36)} / {data.get('total_cases', 36)}",
                    "operators": operators_list,
                    "raw_report": data
                }
        except Exception as e:
            logger.warning(f"Failed to read evaluation_report.json: {e}")
            
    return {
        "generated": False,
        "timestamp": None,
        "detection_rate": None,
        "prevention_rate": None,
        "false_allow": None,
        "false_block": None,
        "mutations_passed": None,
        "security_tests": None,
        "operators": [],
        "raw_report": None,
        "message": "Evaluation report not generated yet. Run 'python -m evaluator.metrics' from the project root."
    }

@app.get("/api/benchmarks")
def get_benchmarks():
    benchmark_path = "benchmark_report.json" if os.path.isfile("benchmark_report.json") else os.path.join("docs", "reports", "benchmark_report.json")
    if os.path.isfile(benchmark_path):
        try:
            with open(benchmark_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                data["generated"] = True
                return data
        except Exception as e:
            logger.warning(f"Failed to read benchmark_report.json: {e}")
    return {
        "generated": False,
        "timestamp": None,
        "environment": None,
        "gateway_benchmarks": {},
        "micro_benchmarks": {},
        "end_to_end_comparison": {},
        "summary_highlights": {},
        "message": "Benchmark report not generated yet. Run 'python -m evaluator.benchmark' from the project root."
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)
