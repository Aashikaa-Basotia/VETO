from pydantic import BaseModel
from typing import Dict, Any

class PolicyRequest(BaseModel):
    agent_id: str
    capability: str
    arguments: Dict[str, Any] = {}

class PolicyDecision(BaseModel):
    decision: str  # "ALLOW" or "BLOCK"
    capability: str
    reason: str

# Configured explicit allowlist for Phase 6
ALLOWED_CAPABILITIES = {
    "default_agent": [
        "get_downstream_status",
        "create_record",
        "list_recent_emails",
        "get_email_metadata",
        "get_email_body",
        "send_email",
        "list_calendar_events",
        "create_calendar_event"
    ]
}

def evaluate_capability(request: PolicyRequest) -> PolicyDecision:
    """
    Evaluates whether an agent is authorized to use a specific capability.
    Must fail closed (default to BLOCK).
    """
    # Defensive check against malformed data explicitly
    if not request.agent_id or not request.capability:
        return PolicyDecision(
            decision="BLOCK",
            capability=request.capability or "unknown",
            reason="Malformed policy request: missing agent_id or capability"
        )
        
    if request.agent_id not in ALLOWED_CAPABILITIES:
        return PolicyDecision(
            decision="BLOCK",
            capability=request.capability,
            reason=f"Unknown agent: {request.agent_id}"
        )
        
    agent_allowed = ALLOWED_CAPABILITIES[request.agent_id]
    
    if request.capability not in agent_allowed:
        return PolicyDecision(
            decision="BLOCK",
            capability=request.capability,
            reason=f"Capability not authorized for agent {request.agent_id}"
        )
        
    return PolicyDecision(
        decision="ALLOW",
        capability=request.capability,
        reason=f"Capability is explicitly allowed for this agent."
    )
