import os
from pydantic import BaseModel

class DestinationResult(BaseModel):
    logical_name: str
    trust_level: str
    endpoint_url: str

DOWNSTREAM_URL = os.environ.get("DOWNSTREAM_URL", "http://127.0.0.1:8000")

DESTINATION_REGISTRY = {
    "controlled_downstream": {
        "trust_level": "TRUSTED",
        "endpoint_url": DOWNSTREAM_URL
    },
    "gmail_api": {
        "trust_level": "TRUSTED",
        "endpoint_url": "https://gmail.googleapis.com"
    },
    "google_calendar_api": {
        "trust_level": "TRUSTED",
        "endpoint_url": "https://www.googleapis.com/calendar/v3"
    }
}

CAPABILITY_DESTINATION_MAP = {
    "get_downstream_status": "controlled_downstream",
    "create_record": "controlled_downstream",
    "delete_record": "controlled_downstream",
    "list_recent_emails": "gmail_api",
    "get_email_metadata": "gmail_api",
    "get_email_body": "gmail_api",
    "send_email": "gmail_api",
    "list_calendar_events": "google_calendar_api",
    "create_calendar_event": "google_calendar_api"
}

def evaluate_destination(capability: str, requested_destination: str = None) -> DestinationResult:
    """
    Evaluates the destination for a given capability.
    Must fail closed (default to UNKNOWN).
    """
    expected_destination = CAPABILITY_DESTINATION_MAP.get(capability)
    
    if requested_destination:
        logical_name = requested_destination
    else:
        logical_name = expected_destination
        
    if not logical_name or logical_name not in DESTINATION_REGISTRY:
        return DestinationResult(
            logical_name=logical_name or "unregistered",
            trust_level="UNKNOWN",
            endpoint_url=""
        )
        
    # Cross-service isolation: Requested destination must match the capability's allowed destination
    if expected_destination and logical_name != expected_destination:
        return DestinationResult(
            logical_name=logical_name,
            trust_level="UNKNOWN_MISMATCH",
            endpoint_url=""
        )
        
    dest_info = DESTINATION_REGISTRY[logical_name]
    return DestinationResult(
        logical_name=logical_name,
        trust_level=dest_info["trust_level"],
        endpoint_url=dest_info["endpoint_url"]
    )
