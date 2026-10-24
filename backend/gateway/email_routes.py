"""
VETO Read-Only Incoming Email Review API (Phase 3).

Exposes endpoints for the VETO Dashboard to inspect incoming email discovery,
deduplication state, AI-generated security classifications, risk levels, and human-review
requirements without introducing autonomous actions or bypassing gateway security boundaries.
"""

import os
import json
import sqlite3
import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("veto_email_api")

router = APIRouter(prefix="/api/emails", tags=["Incoming Emails"])

DISALLOWED_ID_CHARS = ("/", "\\", "?", "&", "\0", "\n", "\r")


def get_db_path() -> str:
    return os.environ.get("VETO_EMAIL_WATCHER_DB", "email_watcher.db")


def get_readonly_connection() -> Optional[sqlite3.Connection]:
    """
    Returns a read-only SQLite connection if database exists, or None.
    Handles missing database gracefully without raising unhandled exceptions.
    """
    db_path = get_db_path()
    if not os.path.exists(db_path):
        return None

    try:
        # Open in URI read-only mode to prevent write lock conflicts with workers
        uri = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logger.debug(f"[VETO][EMAIL_API] Read-only URI connect fallback: {e}")
        try:
            conn = sqlite3.connect(db_path, timeout=5.0)
            conn.row_factory = sqlite3.Row
            return conn
        except Exception as inner_e:
            logger.warning(f"[VETO][EMAIL_API] Database connection error: {inner_e}")
            return None


def sanitize_text(text: Optional[str]) -> str:
    """Sanitizes text by stripping control characters and null bytes."""
    if not text:
        return ""
    return "".join(ch for ch in text if ch in ("\n", "\r", "\t") or ord(ch) >= 32)


def extract_clean_summary(raw: Optional[str]) -> Optional[str]:
    """Extracts clean plain-text summary if LLM returned JSON-wrapped output."""
    if not raw:
        return None
    cleaned = sanitize_text(raw).strip()
    if not cleaned:
        return None
    if cleaned.startswith("{") and cleaned.endswith("}"):
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                val = data.get("summary") or data.get("email_content") or data.get("analysis")
                if isinstance(val, str) and val.strip():
                    return sanitize_text(val).strip()
        except Exception:
            pass
    return cleaned


class EmailSummary(BaseModel):
    total_discovered: int
    processed: int
    processing: int
    discovered: int
    failed: int
    classified_count: int
    by_classification: Dict[str, int]
    by_risk_level: Dict[str, int]
    requires_human_review_count: int
    unprocessed_count: int


class EmailRecord(BaseModel):
    message_id: str
    thread_id: Optional[str] = None
    subject: str
    sender: str
    date: str
    snippet: str
    state: str
    discovered_at: str
    updated_at: str
    retry_count: int
    last_error: Optional[str] = None
    classification: Optional[str] = None
    risk_level: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)
    requires_human_review: bool = False
    processed_at: Optional[str] = None
    classification_status: Optional[str] = None
    failure_reason: Optional[str] = None
    summary: Optional[str] = None


class EmailListResponse(BaseModel):
    items: List[EmailRecord]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("/summary", response_model=EmailSummary)
def get_email_summary():
    """
    Returns aggregated metrics of discovered, processed, and classified emails.
    Clearly distinguishes unprocessed emails from emails classified as SAFE.
    """
    empty_summary = EmailSummary(
        total_discovered=0,
        processed=0,
        processing=0,
        discovered=0,
        failed=0,
        classified_count=0,
        by_classification={"SAFE": 0, "SUSPICIOUS": 0, "NEEDS_REVIEW": 0},
        by_risk_level={"LOW": 0, "MEDIUM": 0, "HIGH": 0},
        requires_human_review_count=0,
        unprocessed_count=0,
    )

    conn = get_readonly_connection()
    if conn is None:
        return empty_summary

    try:
        with conn:
            cursor = conn.cursor()

            # Verify table existence
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='watched_emails'"
            )
            if not cursor.fetchone():
                return empty_summary

            # 1. State counts from watched_emails
            cursor.execute("SELECT state, COUNT(*) FROM watched_emails GROUP BY state")
            state_counts = {row[0]: row[1] for row in cursor.fetchall()}

            total_discovered = sum(state_counts.values())
            processed = state_counts.get("PROCESSED", 0)
            processing = state_counts.get("PROCESSING", 0)
            discovered = state_counts.get("DISCOVERED", 0)
            failed = state_counts.get("FAILED", 0)
            unprocessed_count = discovered + processing + failed

            # 2. Classification counts from email_classifications table (if exists)
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='email_classifications'"
            )
            has_classifications = cursor.fetchone() is not None

            by_classification = {"SAFE": 0, "SUSPICIOUS": 0, "NEEDS_REVIEW": 0}
            by_risk_level = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
            classified_count = 0
            requires_human_review_count = 0

            if has_classifications:
                cursor.execute(
                    "SELECT classification, COUNT(*) FROM email_classifications GROUP BY classification"
                )
                for row in cursor.fetchall():
                    if row[0] in by_classification:
                        by_classification[row[0]] = row[1]

                cursor.execute(
                    "SELECT risk_level, COUNT(*) FROM email_classifications GROUP BY risk_level"
                )
                for row in cursor.fetchall():
                    if row[0] in by_risk_level:
                        by_risk_level[row[0]] = row[1]

                cursor.execute(
                    "SELECT COUNT(*) FROM email_classifications WHERE requires_human_review = 1"
                )
                review_row = cursor.fetchone()
                requires_human_review_count = review_row[0] if review_row else 0

                classified_count = sum(by_classification.values())

            return EmailSummary(
                total_discovered=total_discovered,
                processed=processed,
                processing=processing,
                discovered=discovered,
                failed=failed,
                classified_count=classified_count,
                by_classification=by_classification,
                by_risk_level=by_risk_level,
                requires_human_review_count=requires_human_review_count,
                unprocessed_count=unprocessed_count,
            )
    except Exception as e:
        logger.error(f"[VETO][EMAIL_API] Failed to compute email summary: {e}")
        return empty_summary
    finally:
        conn.close()


@router.get("", response_model=EmailListResponse)
def list_emails(
    page: int = Query(1, ge=1, description="Page number (>=1)"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page (1..100)"),
    classification: Optional[str] = Query(None, description="Filter: SAFE, SUSPICIOUS, NEEDS_REVIEW, UNCLASSIFIED"),
    risk_level: Optional[str] = Query(None, description="Filter: LOW, MEDIUM, HIGH"),
    state: Optional[str] = Query(None, description="Filter: DISCOVERED, PROCESSING, PROCESSED, FAILED"),
    requires_human_review: Optional[bool] = Query(None, description="Filter: true or false"),
    search: Optional[str] = Query(None, description="Search subject, sender, or snippet"),
):
    """
    Paginated read-only list of discovered and classified emails with filtering.
    """
    # Parameter validation
    if classification is not None:
        valid_cls = ("SAFE", "SUSPICIOUS", "NEEDS_REVIEW", "UNCLASSIFIED")
        if classification.upper() not in valid_cls:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid classification filter '{classification}'. Must be one of: {', '.join(valid_cls)}",
            )
        classification = classification.upper()

    if risk_level is not None:
        valid_risk = ("LOW", "MEDIUM", "HIGH")
        if risk_level.upper() not in valid_risk:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid risk_level filter '{risk_level}'. Must be one of: {', '.join(valid_risk)}",
            )
        risk_level = risk_level.upper()

    if state is not None:
        valid_states = ("DISCOVERED", "PROCESSING", "PROCESSED", "FAILED")
        if state.upper() not in valid_states:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid state filter '{state}'. Must be one of: {', '.join(valid_states)}",
            )
        state = state.upper()

    empty_response = EmailListResponse(
        items=[],
        total=0,
        page=page,
        page_size=page_size,
        total_pages=0,
    )

    conn = get_readonly_connection()
    if conn is None:
        return empty_response

    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='watched_emails'"
            )
            if not cursor.fetchone():
                return empty_response

            # Check if email_classifications exists and whether summary column is present
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='email_classifications'"
            )
            has_classifications = cursor.fetchone() is not None

            has_summary = False
            if has_classifications:
                cursor.execute("PRAGMA table_info(email_classifications)")
                existing_cols = [col[1] for col in cursor.fetchall()]
                has_summary = "summary" in existing_cols

            # Construct parameterized WHERE clauses
            where_clauses = []
            params = []

            if state:
                where_clauses.append("w.state = ?")
                params.append(state)

            if has_classifications:
                if classification == "UNCLASSIFIED":
                    where_clauses.append("c.classification IS NULL")
                elif classification:
                    where_clauses.append("c.classification = ?")
                    params.append(classification)

                if risk_level:
                    where_clauses.append("c.risk_level = ?")
                    params.append(risk_level)

                if requires_human_review is not None:
                    where_clauses.append("c.requires_human_review = ?")
                    params.append(1 if requires_human_review else 0)
            else:
                if classification == "UNCLASSIFIED":
                    pass  # all are unclassified
                elif classification or risk_level or requires_human_review is not None:
                    # Filter impossible since no classifications exist
                    return empty_response

            if search:
                cleaned_search = f"%{search.strip()}%"
                where_clauses.append(
                    "(w.subject LIKE ? OR w.sender LIKE ? OR w.snippet LIKE ?)"
                )
                params.extend([cleaned_search, cleaned_search, cleaned_search])

            where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

            # 1. Total count query
            count_sql = f"""
                SELECT COUNT(*)
                FROM watched_emails w
                {'LEFT JOIN email_classifications c ON w.message_id = c.message_id' if has_classifications else ''}
                {where_sql}
            """
            cursor.execute(count_sql, tuple(params))
            total_items = cursor.fetchone()[0]

            if total_items == 0:
                return empty_response

            total_pages = (total_items + page_size - 1) // page_size
            offset = (page - 1) * page_size

            # 2. Paginated items query
            join_clause = "LEFT JOIN email_classifications c ON w.message_id = c.message_id" if has_classifications else ""
            cols = """
                w.message_id, w.thread_id, w.subject, w.sender, w.date, w.snippet,
                w.state, w.discovered_at, w.updated_at, w.retry_count, w.last_error
            """
            if has_classifications:
                summary_col = "c.summary" if has_summary else "NULL AS summary"
                cols += f""",
                    c.classification, c.risk_level, c.reasons, c.requires_human_review,
                    c.processed_at, c.status AS classification_status, c.failure_reason,
                    {summary_col}
                """
            else:
                cols += """,
                    NULL AS classification, NULL AS risk_level, NULL AS reasons,
                    NULL AS requires_human_review, NULL AS processed_at,
                    NULL AS classification_status, NULL AS failure_reason,
                    NULL AS summary
                """

            select_sql = f"""
                SELECT {cols}
                FROM watched_emails w
                {join_clause}
                {where_sql}
                ORDER BY w.discovered_at DESC, w.message_id DESC
                LIMIT ? OFFSET ?
            """
            query_params = list(params) + [page_size, offset]
            cursor.execute(select_sql, tuple(query_params))
            rows = cursor.fetchall()

            items = []
            for row in rows:
                reasons = []
                if row["reasons"]:
                    try:
                        reasons = json.loads(row["reasons"])
                    except Exception:
                        reasons = [row["reasons"]]

                summary_val = None
                if "summary" in row.keys() and row["summary"]:
                    summary_val = extract_clean_summary(row["summary"])

                items.append(
                    EmailRecord(
                        message_id=row["message_id"],
                        thread_id=row["thread_id"],
                        subject=sanitize_text(row["subject"]),
                        sender=sanitize_text(row["sender"]),
                        date=row["date"] or "",
                        snippet=sanitize_text(row["snippet"]),
                        state=row["state"],
                        discovered_at=row["discovered_at"],
                        updated_at=row["updated_at"],
                        retry_count=row["retry_count"] or 0,
                        last_error=row["last_error"],
                        classification=row["classification"],
                        risk_level=row["risk_level"],
                        reasons=reasons,
                        requires_human_review=bool(row["requires_human_review"]),
                        processed_at=row["processed_at"],
                        classification_status=row["classification_status"],
                        failure_reason=row["failure_reason"],
                        summary=summary_val,
                    )
                )

            return EmailListResponse(
                items=items,
                total=total_items,
                page=page,
                page_size=page_size,
                total_pages=total_pages,
            )
    except Exception as e:
        logger.error(f"[VETO][EMAIL_API] Failed to list emails: {e}")
        return empty_response
    finally:
        conn.close()


@router.get("/{message_id}", response_model=EmailRecord)
def get_email_detail(message_id: str):
    """
    Returns full metadata, AI classification, risk level, reasons, and status
    for a specific email message.
    """
    clean_id = message_id.strip()
    if not clean_id or len(clean_id) > 128 or any(c in clean_id for c in DISALLOWED_ID_CHARS):
        raise HTTPException(status_code=400, detail="Invalid message ID format.")

    conn = get_readonly_connection()
    if conn is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='watched_emails'"
            )
            if not cursor.fetchone():
                raise HTTPException(status_code=404, detail="Email not found.")

            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='email_classifications'"
            )
            has_classifications = cursor.fetchone() is not None

            has_summary = False
            if has_classifications:
                cursor.execute("PRAGMA table_info(email_classifications)")
                existing_cols = [col[1] for col in cursor.fetchall()]
                has_summary = "summary" in existing_cols

            join_clause = "LEFT JOIN email_classifications c ON w.message_id = c.message_id" if has_classifications else ""
            cols = """
                w.message_id, w.thread_id, w.subject, w.sender, w.date, w.snippet,
                w.state, w.discovered_at, w.updated_at, w.retry_count, w.last_error
            """
            if has_classifications:
                summary_col = "c.summary" if has_summary else "NULL AS summary"
                cols += f""",
                    c.classification, c.risk_level, c.reasons, c.requires_human_review,
                    c.processed_at, c.status AS classification_status, c.failure_reason,
                    {summary_col}
                """
            else:
                cols += """,
                    NULL AS classification, NULL AS risk_level, NULL AS reasons,
                    NULL AS requires_human_review, NULL AS processed_at,
                    NULL AS classification_status, NULL AS failure_reason,
                    NULL AS summary
                """

            sql = f"""
                SELECT {cols}
                FROM watched_emails w
                {join_clause}
                WHERE w.message_id = ?
            """
            cursor.execute(sql, (clean_id,))
            row = cursor.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Email not found.")

            reasons = []
            if row["reasons"]:
                try:
                    reasons = json.loads(row["reasons"])
                except Exception:
                    reasons = [row["reasons"]]

            summary_val = None
            if "summary" in row.keys() and row["summary"]:
                summary_val = extract_clean_summary(row["summary"])

            return EmailRecord(
                message_id=row["message_id"],
                thread_id=row["thread_id"],
                subject=sanitize_text(row["subject"]),
                sender=sanitize_text(row["sender"]),
                date=row["date"] or "",
                snippet=sanitize_text(row["snippet"]),
                state=row["state"],
                discovered_at=row["discovered_at"],
                updated_at=row["updated_at"],
                retry_count=row["retry_count"] or 0,
                last_error=row["last_error"],
                classification=row["classification"],
                risk_level=row["risk_level"],
                reasons=reasons,
                requires_human_review=bool(row["requires_human_review"]),
                processed_at=row["processed_at"],
                classification_status=row["classification_status"],
                failure_reason=row["failure_reason"],
                summary=summary_val,
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[VETO][EMAIL_API] Failed to get email detail for {clean_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error reading email details.")
    finally:
        conn.close()
