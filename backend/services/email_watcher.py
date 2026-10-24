"""
VETO Incoming Email Watcher & Deduplication Engine (Phase 1).

Autonomous background worker that periodically polls Gmail for incoming emails using
GmailAdapter, enforces deterministic validation, eliminates duplicate processing
via SQLite unique constraints, and maintains state transitions across worker restarts.
"""

import os
import sys
import json
import sqlite3
import logging
import signal
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("veto_email_watcher")


class EmailProcessingState:
    """Explicit lifecycle states for monitored emails."""
    DISCOVERED = "DISCOVERED"    # New email discovered & metadata recorded; pending processing
    PROCESSING = "PROCESSING"    # Currently undergoing processing by downstream pipeline
    PROCESSED = "PROCESSED"      # Successfully processed by agent/pipeline (future phase)
    FAILED = "FAILED"            # Processing failed or errored out; eligible for bounded retry


class EmailValidationError(ValueError):
    """Raised when email metadata fails structural, type, or size constraints."""
    pass


def validate_email_metadata(msg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates and bounds incoming email metadata from GmailAdapter.
    Ensures safe types and strictly bounded field lengths.
    """
    if not isinstance(msg, dict):
        raise EmailValidationError("Message metadata must be a dictionary.")

    # 1. message_id (Primary Key)
    message_id = msg.get("id")
    if not message_id or not isinstance(message_id, str):
        raise EmailValidationError("Missing or non-string message 'id'.")
    message_id = message_id.strip()
    if not message_id or len(message_id) > 128:
        raise EmailValidationError(f"Invalid message 'id' length ({len(message_id)}). Must be 1..128 chars.")
    for char in ("/", "\\", "?", "&", "\0", "\n", "\r"):
        if char in message_id:
            raise EmailValidationError(f"Message 'id' contains disallowed character: {repr(char)}")

    # 2. thread_id
    thread_id = msg.get("threadId")
    if thread_id is not None:
        if not isinstance(thread_id, str) or len(thread_id) > 128:
            raise EmailValidationError("threadId must be a string up to 128 chars.")
        thread_id = thread_id.strip()

    # 3. subject
    subject = msg.get("subject")
    if subject is not None:
        if not isinstance(subject, str):
            raise EmailValidationError("Subject must be a string.")
        if len(subject) > 512:
            subject = subject[:512]

    # 4. sender (From)
    sender = msg.get("from")
    if sender is not None:
        if not isinstance(sender, str):
            raise EmailValidationError("Sender 'from' must be a string.")
        if len(sender) > 320:
            sender = sender[:320]

    # 5. date
    date = msg.get("date")
    if date is not None:
        if not isinstance(date, str):
            raise EmailValidationError("Date must be a string.")
        if len(date) > 128:
            date = date[:128]

    # 6. snippet
    snippet = msg.get("snippet")
    if snippet is not None:
        if not isinstance(snippet, str):
            raise EmailValidationError("Snippet must be a string.")
        if len(snippet) > 1024:
            snippet = snippet[:1024]

    return {
        "id": message_id,
        "threadId": thread_id or "",
        "subject": subject or "",
        "from": sender or "",
        "date": date or "",
        "snippet": snippet or ""
    }


class EmailWatcher:
    """
    Watches a connected Gmail account for incoming messages using GmailAdapter.
    Persists processing state to a dedicated SQLite database with unique constraints.
    """
    def __init__(
        self,
        adapter: Optional[Any] = None,
        db_path: Optional[str] = None,
        poll_interval: Optional[float] = None,
        batch_size: int = 10,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        max_backoff: float = 300.0,
    ):
        self.adapter = adapter
        self.db_path = db_path or os.environ.get("VETO_EMAIL_WATCHER_DB", "email_watcher.db")
        
        # Polling interval configuration (default 30.0 seconds)
        if poll_interval is not None:
            try:
                self.poll_interval = float(poll_interval)
            except (ValueError, TypeError):
                self.poll_interval = 30.0
        else:
            env_interval = os.environ.get("VETO_EMAIL_POLL_INTERVAL", "30.0")
            try:
                self.poll_interval = float(env_interval)
            except (ValueError, TypeError):
                self.poll_interval = 30.0

        if self.poll_interval <= 0:
            self.poll_interval = 30.0

        self.batch_size = max(1, min(batch_size, 20))
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
        
        self._current_backoff = self.poll_interval
        self._consecutive_failures = 0
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self._init_db()

    def _init_db(self):
        """Initializes the SQLite schema with table and indexes."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS watched_emails (
                    message_id TEXT PRIMARY KEY,
                    thread_id TEXT,
                    subject TEXT,
                    sender TEXT,
                    date TEXT,
                    snippet TEXT,
                    state TEXT NOT NULL,
                    discovered_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT
                )
            ''')
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_watched_emails_state 
                ON watched_emails(state)
            ''')
            conn.commit()

    def _get_adapter(self):
        """Lazy load or return the injected GmailAdapter."""
        if self.adapter is None:
            from services.gmail import GmailAdapter
            self.adapter = GmailAdapter()
        return self.adapter

    def register_email(self, raw_msg: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validates and attempts atomic registration of an email in DISCOVERED state.
        Returns:
            (True, "registered") if newly discovered and recorded.
            (False, "already_registered") if message_id already exists.
            (False, f"validation_error: {err}") if invalid.
        """
        try:
            valid_msg = validate_email_metadata(raw_msg)
        except EmailValidationError as e:
            logger.warning(f"[VETO][EMAIL_WATCHER] Discarding malformed message metadata: {e}")
            return False, f"validation_error: {e}"

        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    '''
                    INSERT INTO watched_emails 
                    (message_id, thread_id, subject, sender, date, snippet, state, discovered_at, updated_at, retry_count, last_error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)
                    ''',
                    (
                        valid_msg["id"],
                        valid_msg["threadId"],
                        valid_msg["subject"],
                        valid_msg["from"],
                        valid_msg["date"],
                        valid_msg["snippet"],
                        EmailProcessingState.DISCOVERED,
                        now,
                        now
                    )
                )
                conn.commit()
                logger.info(f"[VETO][EMAIL_WATCHER] Registered new email: id={valid_msg['id']} subject={valid_msg['subject'][:40]}")
                return True, "registered"
            except sqlite3.IntegrityError:
                # Primary key collision: already registered
                return False, "already_registered"

    def update_email_state(
        self,
        message_id: str,
        new_state: str,
        expected_current_state: Optional[str] = None,
        error_msg: Optional[str] = None
    ) -> bool:
        """
        Atomically updates the processing state of an email with timestamp and error info.
        """
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            query = "UPDATE watched_emails SET state = ?, updated_at = ?"
            params = [new_state, now]
            
            if error_msg is not None:
                query += ", last_error = ?, retry_count = retry_count + 1"
                params.append(error_msg[:500])
                
            query += " WHERE message_id = ?"
            params.append(message_id)
            
            if expected_current_state is not None:
                query += " AND state = ?"
                params.append(expected_current_state)
                
            cursor.execute(query, tuple(params))
            conn.commit()
            return cursor.rowcount > 0

    def recover_interrupted_state(self, reset_failed: bool = False) -> int:
        """
        Recovers emails left in PROCESSING state from previous crashes or ungraceful stops.
        Transitions them back to DISCOVERED so they are not silently lost.
        Optionally resets FAILED emails that have not exceeded max_retries.
        """
        recovered_count = 0
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # 1. Recover uncompleted PROCESSING states
            cursor.execute(
                '''
                UPDATE watched_emails 
                SET state = ?, updated_at = ?, last_error = 'Worker interrupted during processing'
                WHERE state = ?
                ''',
                (EmailProcessingState.DISCOVERED, now, EmailProcessingState.PROCESSING)
            )
            recovered_count += cursor.rowcount

            # 2. Optionally recover retryable FAILED states
            if reset_failed:
                cursor.execute(
                    '''
                    UPDATE watched_emails 
                    SET state = ?, updated_at = ?
                    WHERE state = ? AND retry_count < ?
                    ''',
                    (EmailProcessingState.DISCOVERED, now, EmailProcessingState.FAILED, self.max_retries)
                )
                recovered_count += cursor.rowcount
            conn.commit()

        if recovered_count > 0:
            logger.info(f"[VETO][EMAIL_WATCHER] Recovered {recovered_count} interrupted emails to DISCOVERED state.")
        return recovered_count

    def get_email(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single email record by message_id."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM watched_emails WHERE message_id = ?", (message_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def get_emails_by_state(self, state: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves emails matching a specific state."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM watched_emails WHERE state = ? ORDER BY discovered_at ASC LIMIT ?",
                (state, limit)
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def poll_once(self) -> Dict[str, Any]:
        """
        Executes a single check cycle against Gmail:
        1. Fetches recent email metadata via GmailAdapter.list_recent_emails()
        2. Deduplicates against database and registers new emails in DISCOVERED state.
        3. Returns cycle summary metrics.
        """
        adapter = self._get_adapter()
        result = {
            "success": False,
            "discovered": 0,
            "already_seen": 0,
            "errors": 0,
            "error_detail": None
        }

        try:
            resp = adapter.list_recent_emails(max_results=self.batch_size)
        except Exception as e:
            # Catch transient network/API or OAuth errors safely without exposing secrets
            err_type = type(e).__name__
            err_msg = str(e)
            sanitized_err = f"{err_type}: {err_msg}"
            logger.warning(f"[VETO][EMAIL_WATCHER] Gmail polling error: {sanitized_err}")
            result["error_detail"] = sanitized_err
            self._handle_failure()
            return result

        if not isinstance(resp, dict):
            logger.warning("[VETO][EMAIL_WATCHER] Invalid response structure from GmailAdapter.")
            result["error_detail"] = "Invalid response structure from GmailAdapter"
            self._handle_failure()
            return result

        raw_messages = resp.get("messages", [])
        if not isinstance(raw_messages, list):
            raw_messages = []

        for msg in raw_messages:
            success, reason = self.register_email(msg)
            if success:
                result["discovered"] += 1
            elif reason == "already_registered":
                result["already_seen"] += 1
            else:
                result["errors"] += 1

        result["success"] = True
        self._handle_success()
        return result

    def _handle_success(self):
        """Resets backoff counters after a successful poll."""
        self._consecutive_failures = 0
        self._current_backoff = self.poll_interval

    def _handle_failure(self):
        """Increments failure count and computes bounded exponential backoff."""
        self._consecutive_failures += 1
        new_backoff = min(
            self.poll_interval * (self.backoff_factor ** self._consecutive_failures),
            self.max_backoff
        )
        self._current_backoff = new_backoff
        logger.info(f"[VETO][EMAIL_WATCHER] Failure backoff applied. Next check in {self._current_backoff:.1f}s.")

    def run(self, max_cycles: Optional[int] = None):
        """
        Continuous worker loop. Periodically executes poll_once().
        Runs until self.stop() is called or max_cycles is reached.
        """
        logger.info(f"[VETO][EMAIL_WATCHER] Starting watcher. Interval={self.poll_interval}s DB={self.db_path}")
        
        # Initial recovery of any crashed/interrupted processing states
        self.recover_interrupted_state()
        
        cycles = 0
        while not self._stop_event.is_set():
            cycles += 1
            logger.info(f"[VETO][EMAIL_WATCHER] Polling cycle #{cycles}...")
            
            summary = self.poll_once()
            logger.info(
                f"[VETO][EMAIL_WATCHER] Cycle #{cycles} complete: "
                f"discovered={summary['discovered']} already_seen={summary['already_seen']} "
                f"errors={summary['errors']} success={summary['success']}"
            )
            
            if max_cycles is not None and cycles >= max_cycles:
                logger.info(f"[VETO][EMAIL_WATCHER] Reached max_cycles ({max_cycles}). Exiting.")
                break

            # Sleep with interruptible stop_event
            sleep_time = self._current_backoff
            if self._stop_event.wait(timeout=sleep_time):
                logger.info("[VETO][EMAIL_WATCHER] Received stop signal during sleep. Exiting.")
                break

    def stop(self):
        """Signals the worker loop to stop gracefully."""
        logger.info("[VETO][EMAIL_WATCHER] Stopping watcher gracefully...")
        self._stop_event.set()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    logger.info("[VETO][EMAIL_WATCHER] Initializing VETO Email Watcher Daemon...")
    watcher = EmailWatcher()

    def handle_exit_signal(sig, frame):
        logger.info(f"[VETO][EMAIL_WATCHER] Caught exit signal ({sig}), initiating shutdown...")
        watcher.stop()

    try:
        signal.signal(signal.SIGINT, handle_exit_signal)
        signal.signal(signal.SIGTERM, handle_exit_signal)
    except (ValueError, AttributeError):
        pass

    try:
        watcher.run()
    except KeyboardInterrupt:
        watcher.stop()


if __name__ == "__main__":
    main()
