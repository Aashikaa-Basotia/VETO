import sqlite3
import os
import time

class ReplayEngine:
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.environ.get("VETO_REPLAY_DB", "replay.db")
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS replay_state (
                    request_id TEXT PRIMARY KEY,
                    agent_id TEXT,
                    operation TEXT,
                    first_seen REAL
                )
            ''')
            conn.commit()

    def check_and_consume(self, request_id: str, agent_id: str, operation: str) -> bool:
        """
        Atomically checks if a request_id is fresh, and consumes it if it is.
        Returns True if fresh (allowed), False if already consumed (replayed/blocked).
        """
        if not request_id:
            return False

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                # Atomically insert if it doesn't exist. The UNIQUE constraint on request_id handles the concurrency safety.
                cursor.execute(
                    "INSERT INTO replay_state (request_id, agent_id, operation, first_seen) VALUES (?, ?, ?, ?)",
                    (request_id, agent_id, operation, time.time())
                )
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                # Primary key collision -> Replay detected
                return False

    def clear(self):
        # Used strictly for tests/cleanup
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM replay_state")
            conn.commit()

def get_replay_engine() -> ReplayEngine:
    return ReplayEngine()
