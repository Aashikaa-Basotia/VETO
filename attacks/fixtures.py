from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel

class AttackCategory(str, Enum):
    PROVENANCE = "PROVENANCE"
    CAPABILITY = "CAPABILITY"
    DESTINATION = "DESTINATION"
    RISK = "RISK"
    CONTEXT = "CONTEXT"
    GMAIL = "GMAIL"
    CALENDAR = "CALENDAR"
    APPROVAL = "APPROVAL"
    CONTROL = "CONTROL"

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AttackFixture(BaseModel):
    fixture_id: str
    name: str
    category: AttackCategory
    description: str
    target_capability: str
    input_payload: Dict[str, Any]
    expected_decision: str  # "ALLOW", "BLOCK", "REQUIRE_APPROVAL"
    expected_block_stage: str # e.g. "provenance", "capability", "destination", "risk", "context", "approval", "adapter_validation", "none"
    expected_downstream_contact: bool
    severity: Severity

ATTACK_FIXTURES = [
    # PROVENANCE
    AttackFixture(
        fixture_id="ATK-PROV-001",
        name="Missing Provenance Signature",
        category=AttackCategory.PROVENANCE,
        description="Request contains no provenance signature.",
        target_capability="get_downstream_status",
        input_payload={"operation": "get_downstream_status", "arguments": {}},
        expected_decision="BLOCK",
        expected_block_stage="provenance",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-PROV-002",
        name="Invalid Provenance Signature",
        category=AttackCategory.PROVENANCE,
        description="Use a fake/invalid signature.",
        target_capability="get_downstream_status",
        input_payload={"operation": "get_downstream_status", "arguments": {}, "provenance_signature": "fake_invalid_sig_123"},
        expected_decision="BLOCK",
        expected_block_stage="provenance",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-PROV-003",
        name="Tampered Signed Request",
        category=AttackCategory.PROVENANCE,
        description="A valid signature is sent with a modified operation.",
        target_capability="delete_record",
        input_payload={"operation": "delete_record", "arguments": {}, "request_id": "REQ-8e347f9f-8cfb-4a07-a16f-945fb409ebe2", "provenance_signature": "signature_for_get_status"},
        expected_decision="BLOCK",
        expected_block_stage="provenance",
        expected_downstream_contact=False,
        severity=Severity.CRITICAL
    ),
    AttackFixture(
        fixture_id="ATK-PROV-004",
        name="Malformed Provenance Signature",
        category=AttackCategory.PROVENANCE,
        description="Signature structural format is entirely wrong.",
        target_capability="get_downstream_status",
        input_payload={"operation": "get_downstream_status", "arguments": {}, "provenance_signature": "!!malformed!!"},
        expected_decision="BLOCK",
        expected_block_stage="provenance",
        expected_downstream_contact=False,
        severity=Severity.MEDIUM
    ),

    # CAPABILITY
    AttackFixture(
        fixture_id="ATK-CAP-001",
        name="Unauthorized Delete",
        category=AttackCategory.CAPABILITY,
        description="Attempt to execute unauthorized destructive capability.",
        target_capability="delete_record",
        input_payload={"operation": "delete_record", "arguments": {}, "request_id": "REQ-e2fddbde-c99a-4d09-83a4-741628b91c02", "request_id": "REQ-5e809b21-6f7d-43fd-959f-e38621a474f1"},
        expected_decision="BLOCK",
        expected_block_stage="capability",
        expected_downstream_contact=False,
        severity=Severity.CRITICAL
    ),
    AttackFixture(
        fixture_id="ATK-CAP-002",
        name="Unknown Capability",
        category=AttackCategory.CAPABILITY,
        description="Attempt to invoke a capability that does not exist.",
        target_capability="hack_system",
        input_payload={"operation": "hack_system", "arguments": {}},
        expected_decision="BLOCK",
        expected_block_stage="capability",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-CAP-003",
        name="Arbitrary Capability/Path Request",
        category=AttackCategory.CAPABILITY,
        description="Attempt path traversal via capability field.",
        target_capability="../../../etc/passwd",
        input_payload={"operation": "../../../etc/passwd", "arguments": {}},
        expected_decision="BLOCK",
        expected_block_stage="capability",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),

    # DESTINATION
    AttackFixture(
        fixture_id="ATK-DEST-001",
        name="Unknown Destination",
        category=AttackCategory.DESTINATION,
        description="Redirect to an unknown logical destination.",
        target_capability="create_record",
        input_payload={"operation": "create_record", "arguments": {"name": "x", "value": "y"}, "request_id": "REQ-7e01627b-9761-478c-8635-f1249a160739", "destination_override": "evil_destination"},
        expected_decision="BLOCK",
        expected_block_stage="destination",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-DEST-002",
        name="Destination Override",
        category=AttackCategory.DESTINATION,
        description="Attempt to override destination dynamically to a bypassed target.",
        target_capability="get_downstream_status",
        input_payload={"operation": "get_downstream_status", "arguments": {}, "destination_override": "unregistered_target"},
        expected_decision="BLOCK",
        expected_block_stage="destination",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-DEST-003",
        name="Arbitrary URL",
        category=AttackCategory.DESTINATION,
        description="Attempt SSRF via explicit URL override.",
        target_capability="get_downstream_status",
        input_payload={"operation": "get_downstream_status", "arguments": {}, "destination_override": "http://127.0.0.1:9999"},
        expected_decision="BLOCK",
        expected_block_stage="destination",
        expected_downstream_contact=False,
        severity=Severity.CRITICAL
    ),

    # RISK
    AttackFixture(
        fixture_id="ATK-RISK-001",
        name="High-Risk Capability",
        category=AttackCategory.RISK,
        description="Directly attempt a capability mapped to HIGH risk.",
        target_capability="delete_record",
        input_payload={"operation": "delete_record", "arguments": {}, "request_id": "REQ-76e43d73-8c38-408e-ae21-89c5807b5746", "request_id": "REQ-101"},
        expected_decision="BLOCK",
        expected_block_stage="capability",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-RISK-002",
        name="Unknown Capability Risk",
        category=AttackCategory.RISK,
        description="Attempt unknown capability causing risk to fail closed.",
        target_capability="unknown_operation",
        input_payload={"operation": "unknown_operation", "arguments": {}},
        expected_decision="BLOCK",
        expected_block_stage="capability",
        expected_downstream_contact=False,
        severity=Severity.MEDIUM
    ),

    # CONTEXT
    AttackFixture(
        fixture_id="ATK-CTX-001",
        name="Restricted State-Changing Operation",
        category=AttackCategory.CONTEXT,
        description="Attempt create_record under a restricted context.",
        target_capability="create_record",
        input_payload={"operation": "create_record", "arguments": {"name": "test", "value": "x"}, "request_id": "REQ-3c854a16-ea49-47df-b6c7-78b03dd5426c", "execution_mode_override": "restricted"},
        expected_decision="BLOCK",
        expected_block_stage="context",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-CTX-002",
        name="Restricted Send Email",
        category=AttackCategory.CONTEXT,
        description="Attempt send_email under restricted execution mode.",
        target_capability="send_email",
        input_payload={"operation": "send_email", "arguments": {"to": "a@b.com", "subject": "test", "body": "test"}, "request_id": "REQ-e6fd97c8-f794-4378-8e08-c8d58244ffa7", "execution_mode_override": "restricted"},
        expected_decision="BLOCK",
        expected_block_stage="context",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-CTX-003",
        name="Agent Payload Context Manipulation",
        category=AttackCategory.CONTEXT,
        description="Agent tries to inject execution_mode via standard arguments.",
        target_capability="create_record",
        input_payload={"operation": "create_record", "arguments": {"name": "test", "value": "x", "execution_mode": "normal"}, "request_id": "REQ-a862d5f7-4c31-4719-b76e-b5ccd5b35b50", "execution_mode_override": "restricted"},
        expected_decision="BLOCK",
        expected_block_stage="context",
        expected_downstream_contact=False,
        severity=Severity.CRITICAL
    ),

    # GMAIL
    AttackFixture(
        fixture_id="ATK-GMAIL-001",
        name="Invalid Message ID Path Traversal",
        category=AttackCategory.GMAIL,
        description="Path traversal injection in message ID.",
        target_capability="get_email_metadata",
        input_payload={"operation": "get_email_metadata", "arguments": {"message_id": "../etc/passwd"}},
        expected_decision="BLOCK",
        expected_block_stage="adapter_validation",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-GMAIL-002",
        name="Query/Path Injection",
        category=AttackCategory.GMAIL,
        description="Inject query parameters into message ID.",
        target_capability="get_email_metadata",
        input_payload={"operation": "get_email_metadata", "arguments": {"message_id": "123?alt=json&attack=1"}},
        expected_decision="BLOCK",
        expected_block_stage="adapter_validation",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-GMAIL-003",
        name="Invalid Recipient",
        category=AttackCategory.GMAIL,
        description="Malformed recipient data.",
        target_capability="send_email",
        input_payload={"operation": "send_email", "arguments": {"to": "not_an_email\r\n", "subject": "test", "body": "test"}, "request_id": "REQ-9fb75c5e-0700-4216-a141-32cd3e8ee7de", "request_id": "REQ-5cfa4e2d-87ba-4e61-85f9-a10061cf3235"},
        expected_decision="BLOCK",
        expected_block_stage="adapter_validation",
        expected_downstream_contact=False,
        severity=Severity.LOW
    ),
    AttackFixture(
        fixture_id="ATK-GMAIL-004",
        name="CR/LF Injection",
        category=AttackCategory.GMAIL,
        description="Header injection via CR/LF in subject.",
        target_capability="send_email",
        input_payload={"operation": "send_email", "arguments": {"to": "a@b.com", "subject": "Hello\r\nBcc: hacker@evil.com", "body": "test"}, "request_id": "REQ-8d672048-013a-4faa-b62f-8237901e5c9e", "request_id": "REQ-6e2244d7-50b7-4083-a620-1b3ed661e799"},
        expected_decision="BLOCK",
        expected_block_stage="adapter_validation",
        expected_downstream_contact=False,
        severity=Severity.CRITICAL
    ),
    AttackFixture(
        fixture_id="ATK-GMAIL-005",
        name="Oversized Subject",
        category=AttackCategory.GMAIL,
        description="Subject exceeding limits.",
        target_capability="send_email",
        input_payload={"operation": "send_email", "arguments": {"to": "a@b.com", "subject": "A" * 300, "body": "test"}, "request_id": "REQ-b26313f9-9be2-4bcb-b3ee-f1250d73222a", "request_id": "REQ-4521bf6a-cc7e-42bf-973e-c6014df295bd"},
        expected_decision="BLOCK",
        expected_block_stage="adapter_validation",
        expected_downstream_contact=False,
        severity=Severity.MEDIUM
    ),
    AttackFixture(
        fixture_id="ATK-GMAIL-006",
        name="Oversized Body",
        category=AttackCategory.GMAIL,
        description="Body exceeding limits.",
        target_capability="send_email",
        input_payload={"operation": "send_email", "arguments": {"to": "a@b.com", "subject": "test", "body": "A" * (101 * 1024)}, "request_id": "REQ-aa843eb1-5378-4392-8f30-f679029ec5ca", "request_id": "REQ-bb1dd248-29cd-4372-b196-0ddc22c3c557"},
        expected_decision="BLOCK",
        expected_block_stage="adapter_validation",
        expected_downstream_contact=False,
        severity=Severity.MEDIUM
    ),

    # APPROVAL
    AttackFixture(
        fixture_id="ATK-APP-001",
        name="Fake Approval ID",
        category=AttackCategory.APPROVAL,
        description="Attempt to pass a non-existent approval ID directly.",
        target_capability="create_record",
        input_payload={"operation": "create_record", "arguments": {"name": "test", "value": "x", "approval_id": "APR-FAKE"}, "request_id": "REQ-96299dfc-c178-4661-b869-1865d6aa4c18", "request_id": "REQ-c8e8a391-695e-4eeb-ac34-4b704c79f5e1"},
        expected_decision="REQUIRE_APPROVAL",
        expected_block_stage="approval",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-APP-002",
        name="Tampered Approved Request",
        category=AttackCategory.APPROVAL,
        description="Change arguments after gaining an approval ID.",
        target_capability="create_record",
        input_payload={"operation": "create_record", "arguments": {"name": "test", "value": "tampered"}, "request_id": "REQ-64adb9b1-6f67-41be-92cb-c534f29094fc", "request_id": "REQ-b14cc10e-bd06-40f6-ac4d-67139f44affe"},
        expected_decision="REQUIRE_APPROVAL",
        expected_block_stage="approval",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-APP-003",
        name="Approval Bypass Flag",
        category=AttackCategory.APPROVAL,
        description="Agent sets 'approved': true in payload.",
        target_capability="create_record",
        input_payload={"operation": "create_record", "arguments": {"name": "test", "value": "x", "approved": True}, "request_id": "REQ-f32e356d-d57d-4169-8e3b-ed5b84937cf4", "request_id": "REQ-ef30e04e-e0d0-481d-9ce1-0810ff31320a"},
        expected_decision="REQUIRE_APPROVAL",
        expected_block_stage="approval",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-APP-004",
        name="Unauthorized Approval Transition",
        category=AttackCategory.APPROVAL,
        description="Invalid manual approval transition representation.",
        target_capability="create_record",
        input_payload={"operation": "create_record", "arguments": {"name": "test", "value": "x", "status": "APPROVED"}, "request_id": "REQ-23142b36-d6dd-4d12-9a48-e28d7482ddd3", "request_id": "REQ-c3584aff-2987-4f38-a7d7-2a7da283ff97"},
        expected_decision="REQUIRE_APPROVAL",
        expected_block_stage="approval",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-APP-005",
        name="Approval Cannot Bypass Restricted Context",
        category=AttackCategory.APPROVAL,
        description="Even with a theoretically valid payload, context should block it first.",
        target_capability="send_email",
        input_payload={"operation": "send_email", "arguments": {"to": "a@b.com", "subject": "test", "body": "test"}, "request_id": "REQ-3f3888bb-b2a9-444b-baeb-e36abef85cdc", "execution_mode_override": "restricted"},
        expected_decision="BLOCK",
        expected_block_stage="context",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),

    # CALENDAR
    AttackFixture(
        fixture_id="ATK-CAL-001",
        name="Calendar Unauthorized Capability",
        category=AttackCategory.CALENDAR,
        description="Attempt to execute unknown Calendar operation.",
        target_capability="delete_calendar_event",
        input_payload={"operation": "delete_calendar_event", "arguments": {"eventId": "123"}, "request_id": "REQ-CAL-1"},
        expected_decision="BLOCK",
        expected_block_stage="capability",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-CAL-002",
        name="Calendar Arbitrary Destination Override",
        category=AttackCategory.CALENDAR,
        description="Attempt to redirect calendar API host.",
        target_capability="list_calendar_events",
        input_payload={"operation": "list_calendar_events", "arguments": {}, "destination_override": "http://evil.com"},
        expected_decision="BLOCK",
        expected_block_stage="destination",
        expected_downstream_contact=False,
        severity=Severity.CRITICAL
    ),
    AttackFixture(
        fixture_id="ATK-CAL-003",
        name="Calendar Restricted Mode Write",
        category=AttackCategory.CALENDAR,
        description="Attempt to create calendar event in restricted mode.",
        target_capability="create_calendar_event",
        input_payload={"operation": "create_calendar_event", "arguments": {"summary": "Hacked", "start": {}, "end": {}}, "request_id": "REQ-CAL-2", "execution_mode_override": "restricted"},
        expected_decision="BLOCK",
        expected_block_stage="context",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),

    # CONTROL
    AttackFixture(
        fixture_id="ATK-CTRL-001",
        name="Legitimate Read",
        category=AttackCategory.CONTROL,
        description="Standard allowed read capability.",
        target_capability="get_downstream_status",
        input_payload={"operation": "get_downstream_status", "arguments": {}},
        expected_decision="ALLOW",
        expected_block_stage="none",
        expected_downstream_contact=True,
        severity=Severity.LOW
    ),
    AttackFixture(
        fixture_id="ATK-CTRL-002",
        name="Legitimate Approval-Required Request",
        category=AttackCategory.CONTROL,
        description="Valid state change requiring human approval.",
        target_capability="create_record",
        input_payload={"operation": "create_record", "arguments": {"name": "legit", "value": "req"}, "request_id": "REQ-8e904220-ac15-428d-a312-8112579bd5c7", "request_id": "REQ-326ec4e3-cd6e-45d2-a16a-fe702d1d4dbc"},
        expected_decision="REQUIRE_APPROVAL",
        expected_block_stage="approval",
        expected_downstream_contact=False,
        severity=Severity.LOW
    ),
    AttackFixture(
        fixture_id="ATK-XSRV-001",
        name="Gmail capability to Calendar destination",
        category=AttackCategory.DESTINATION,
        description="Attempt to route a Gmail capability to the Google Calendar API.",
        target_capability="list_recent_emails",
        input_payload={
            "operation": "list_recent_emails",
            "arguments": {},
            "destination_override": "google_calendar_api"
        },
        expected_decision="BLOCK",
        expected_block_stage="destination",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-XSRV-002",
        name="Calendar capability to Gmail destination",
        category=AttackCategory.DESTINATION,
        description="Attempt to route a Calendar capability to the Gmail API.",
        target_capability="list_calendar_events",
        input_payload={
            "operation": "list_calendar_events",
            "arguments": {},
            "destination_override": "gmail_api"
        },
        expected_decision="BLOCK",
        expected_block_stage="destination",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-XSRV-003",
        name="Downstream capability to Gmail destination",
        category=AttackCategory.DESTINATION,
        description="Attempt to route a downstream capability to the Gmail API.",
        target_capability="get_downstream_status",
        input_payload={
            "operation": "get_downstream_status",
            "arguments": {},
            "destination_override": "gmail_api"
        },
        expected_decision="BLOCK",
        expected_block_stage="destination",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-XSRV-004",
        name="Gmail capability to downstream destination",
        category=AttackCategory.DESTINATION,
        description="Attempt to route a Gmail capability to the downstream service.",
        target_capability="list_recent_emails",
        input_payload={
            "operation": "list_recent_emails",
            "arguments": {},
            "destination_override": "controlled_downstream"
        },
        expected_decision="BLOCK",
        expected_block_stage="destination",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    ),
    AttackFixture(
        fixture_id="ATK-XSRV-005",
        name="Calendar capability to downstream destination",
        category=AttackCategory.DESTINATION,
        description="Attempt to route a Calendar capability to the downstream service.",
        target_capability="list_calendar_events",
        input_payload={
            "operation": "list_calendar_events",
            "arguments": {},
            "destination_override": "controlled_downstream"
        },
        expected_decision="BLOCK",
        expected_block_stage="destination",
        expected_downstream_contact=False,
        severity=Severity.HIGH
    )
]

def get_all_fixtures():
    return ATTACK_FIXTURES
