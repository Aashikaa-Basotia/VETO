from pydantic import BaseModel

class RiskResult(BaseModel):
    capability: str
    risk_level: str  # LOW, MEDIUM, HIGH

RISK_REGISTRY = {
    "get_downstream_status": "LOW",    # Read-only operation
    "create_record": "MEDIUM",         # State-changing operation
    "delete_record": "HIGH",           # Destructive operation
    "list_recent_emails": "LOW",       # Read-only metadata operation
    "get_email_metadata": "LOW",       # Read-only metadata operation
    "get_email_body": "LOW",           # Read-only body operation
    "send_email": "MEDIUM",            # State-changing external side effect
    "list_calendar_events": "LOW",     # Read-only calendar
    "create_calendar_event": "MEDIUM"  # State-changing calendar
}

def evaluate_risk(capability: str) -> RiskResult:
    """
    Evaluates the risk level for a given capability.
    Must fail closed (default to HIGH risk for unknown operations).
    """
    if capability not in RISK_REGISTRY:
        return RiskResult(capability=capability, risk_level="HIGH")
        
    return RiskResult(capability=capability, risk_level=RISK_REGISTRY[capability])
