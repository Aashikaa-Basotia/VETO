from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import uuid
import sqlite3
import json
import os

class ProvenanceAudit(BaseModel):
    verification: str

class CapabilityAudit(BaseModel):
    decision: str

class DestinationAudit(BaseModel):
    trust: str

class RiskAudit(BaseModel):
    level: str

class ContextAudit(BaseModel):
    decision: str

class ApprovalAudit(BaseModel):
    approval_id: Optional[str] = None
    status: Optional[str] = None
    request_hash: Optional[str] = None

class ReplayAudit(BaseModel):
    request_id: Optional[str] = None
    decision: Optional[str] = None

class AuditEvent(BaseModel):
    event_id: str
    timestamp: str
    agent_id: str
    operation: str
    
    provenance: Optional[ProvenanceAudit] = None
    replay: Optional[ReplayAudit] = None
    capability: Optional[CapabilityAudit] = None
    destination: Optional[DestinationAudit] = None
    risk: Optional[RiskAudit] = None
    context: Optional[ContextAudit] = None
    approval: Optional[ApprovalAudit] = None
    
    final_decision: str
    reason: str
    downstream_executed: bool


class AuditLogger:
    def __init__(self, db_path: str = "audit.db"):
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    agent_id TEXT,
                    operation TEXT,
                    final_decision TEXT,
                    reason TEXT,
                    event_data TEXT
                )
            ''')
            conn.commit()
            
    def record_event(self, event: AuditEvent):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO audit_events 
                (event_id, timestamp, agent_id, operation, final_decision, reason, event_data) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    event.event_id, 
                    event.timestamp, 
                    event.agent_id, 
                    event.operation, 
                    event.final_decision,
                    event.reason,
                    event.model_dump_json()
                )
            )
            conn.commit()
            
    def get_events(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_data FROM audit_events ORDER BY timestamp ASC")
            rows = cursor.fetchall()
            return [AuditEvent.model_validate_json(row[0]) for row in rows]

# Global singleton
_audit_logger = None

def get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        db_path = os.environ.get("VETO_AUDIT_DB", "audit.db")
        _audit_logger = AuditLogger(db_path)
    return _audit_logger

def create_event(
    operation: str,
    agent_id: str = "default_agent",
    request_id: Optional[str] = None,
    provenance_ver: Optional[str] = None,
    replay_decision: Optional[str] = None,
    cap_decision: Optional[str] = None,
    dest_trust: Optional[str] = None,
    risk_lvl: Optional[str] = None,
    context_decision: Optional[str] = None,
    approval_id: Optional[str] = None,
    approval_status: Optional[str] = None,
    request_hash: Optional[str] = None,
    final_decision: str = "BLOCK",
    reason: str = "unknown",
    downstream_executed: bool = False
) -> AuditEvent:
    """Helper to generate a structured audit event."""
    
    event = AuditEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id=agent_id,
        operation=operation,
        final_decision=final_decision,
        reason=reason,
        downstream_executed=downstream_executed
    )
    
    if provenance_ver:
        event.provenance = ProvenanceAudit(verification=provenance_ver)
    if request_id or replay_decision:
        event.replay = ReplayAudit(request_id=request_id, decision=replay_decision)
    if cap_decision:
        event.capability = CapabilityAudit(decision=cap_decision)
    if dest_trust:
        event.destination = DestinationAudit(trust=dest_trust)
    if risk_lvl:
        event.risk = RiskAudit(level=risk_lvl)
    if context_decision:
        event.context = ContextAudit(decision=context_decision)
    if approval_id or approval_status or request_hash:
        event.approval = ApprovalAudit(
            approval_id=approval_id,
            status=approval_status,
            request_hash=request_hash
        )
        
    return event
