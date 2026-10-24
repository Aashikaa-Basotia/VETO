import os
from pydantic import BaseModel

class SecurityContext(BaseModel):
    agent_id: str
    environment: str
    execution_mode: str

class ContextDecision(BaseModel):
    decision: str
    capability: str
    reason: str
    environment: str
    execution_mode: str

def get_trusted_context(agent_id: str = "default_agent") -> SecurityContext:
    """
    Returns the trusted VETO security context, entirely independent of the LLM payload.
    It reads from the trusted execution environment.
    """
    environment = os.environ.get("VETO_ENVIRONMENT", "local")
    execution_mode = os.environ.get("VETO_EXECUTION_MODE", "normal")
    
    return SecurityContext(
        agent_id=agent_id,
        environment=environment,
        execution_mode=execution_mode
    )

def evaluate_context(capability: str, context: SecurityContext) -> ContextDecision:
    """
    Evaluates if the capability is authorized in the given security context.
    Must fail-closed (BLOCK by default for unknown modes).
    """
    # Fail closed for unknown environments
    if context.environment not in ["local"]:
        return ContextDecision(
            decision="BLOCK",
            capability=capability,
            reason="unknown_environment",
            environment=context.environment,
            execution_mode=context.execution_mode
        )
        
    # Fail closed for unknown execution modes
    if context.execution_mode not in ["normal", "restricted"]:
        return ContextDecision(
            decision="BLOCK",
            capability=capability,
            reason="unknown_execution_mode",
            environment=context.environment,
            execution_mode=context.execution_mode
        )
        
    # Context Rule 1: Restricted mode blocks state-changing operations
    if context.execution_mode == "restricted":
        # In restricted mode, we only allow get_downstream_status (read), list_recent_emails (read), get_email_metadata (read), get_email_body (read), list_calendar_events (read)
        if capability not in ["get_downstream_status", "list_recent_emails", "get_email_metadata", "get_email_body", "list_calendar_events"]:
            return ContextDecision(
                decision="BLOCK",
                capability=capability,
                reason="state_changing_operation_blocked_in_restricted_mode",
                environment=context.environment,
                execution_mode=context.execution_mode
            )
            
    # Default ALLOW if all structural checks and mode rules pass
    return ContextDecision(
        decision="ALLOW",
        capability=capability,
        reason="context_authorized",
        environment=context.environment,
        execution_mode=context.execution_mode
    )
