import os
import sqlite3
import uuid
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional

APPROVAL_REQUIRED_CAPABILITIES = {
    "create_record",
    "send_email",
    "create_calendar_event"
}

def requires_approval(operation: str) -> bool:
    """Determine if a capability requires human approval."""
    return operation in APPROVAL_REQUIRED_CAPABILITIES

def generate_request_hash(agent_id: str, operation: str, arguments: Dict[str, Any]) -> str:
    """Deterministically hash the request to bind approval to exact arguments."""
    canonical_args = json.dumps(arguments, sort_keys=True)
    payload = f"{agent_id}:{operation}:{canonical_args}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

class ApprovalEngine:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get("VETO_APPROVAL_DB", "approval.db")
        self._init_db()
        
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS approval_requests (
                    approval_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    agent_id TEXT,
                    operation TEXT,
                    request_hash TEXT,
                    status TEXT
                )
            ''')
            conn.commit()

    def create_approval_request(self, agent_id: str, operation: str, arguments: Dict[str, Any]) -> str:
        req_hash = generate_request_hash(agent_id, operation, arguments)
        approval_id = f"APR-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO approval_requests 
                (approval_id, timestamp, agent_id, operation, request_hash, status) 
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (approval_id, timestamp, agent_id, operation, req_hash, "PENDING")
            )
            conn.commit()
            
        return approval_id

    def get_approval_status(self, approval_id: str) -> Optional[str]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM approval_requests WHERE approval_id = ?", (approval_id,))
            row = cursor.fetchone()
            if row:
                return row[0]
            return None

    def get_all_approvals(self) -> list:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT approval_id, timestamp, agent_id, operation, request_hash, status FROM approval_requests ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def update_approval_status(self, approval_id: str, new_status: str) -> bool:
        """Update an existing approval status if it is currently PENDING."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Only allow transition from PENDING
            cursor.execute(
                "UPDATE approval_requests SET status = ? WHERE approval_id = ? AND status = 'PENDING'",
                (new_status, approval_id)
            )
            conn.commit()
            return cursor.rowcount > 0

    def check_approval(self, agent_id: str, operation: str, arguments: Dict[str, Any]) -> bool:
        """Check if an exactly matching request has been APPROVED."""
        req_hash = generate_request_hash(agent_id, operation, arguments)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT status FROM approval_requests WHERE agent_id = ? AND operation = ? AND request_hash = ? AND status = 'APPROVED'",
                (agent_id, operation, req_hash)
            )
            return cursor.fetchone() is not None

# Global singleton
_approval_engine = None

def get_approval_engine() -> ApprovalEngine:
    global _approval_engine
    if _approval_engine is None:
        _approval_engine = ApprovalEngine()
    return _approval_engine
