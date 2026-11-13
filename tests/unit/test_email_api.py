"""
Unit tests for VETO Phase 3: Incoming Email Review Read-Only API.

Validates:
1. Summary endpoint with empty database.
2. Summary endpoint with mixed classifications and states.
3. Correct classification and risk filtering.
4. Correct human-review filtering.
5. Pagination and invalid parameters handling.
6. Detail lookup for existing, nonexistent, and malformed message IDs.
7. Detail lookup for emails without classification records (unclassified).
8. Safe handling of database errors and missing files.
9. No sensitive credentials or full email bodies exposed by the API.
"""

import os
import json
import sqlite3
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from gateway.gateway import app

client = TestClient(app)


def _init_test_email_db(db_path: str, with_summary_col: bool = True):
    """Initializes schema and tables for testing."""
    with sqlite3.connect(db_path) as conn:
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
        summary_clause = ", summary TEXT" if with_summary_col else ""
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS email_classifications (
                message_id TEXT PRIMARY KEY,
                classification TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                reasons TEXT NOT NULL,
                requires_human_review INTEGER NOT NULL,
                processed_at TEXT NOT NULL,
                status TEXT NOT NULL,
                failure_reason TEXT
                {summary_clause},
                FOREIGN KEY(message_id) REFERENCES watched_emails(message_id)
            )
        ''')
        conn.commit()


def _insert_test_email(
    db_path: str,
    message_id: str,
    subject: str,
    sender: str,
    state: str,
    snippet: str = "Test snippet",
    classification: str = None,
    risk_level: str = None,
    reasons: list = None,
    requires_human_review: bool = False,
    discovered_at: str = "2026-10-15T10:00:00Z",
    processed_at: str = "2026-10-15T10:00:05Z",
    failure_reason: str = None,
    summary: str = None,
):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            '''
            INSERT INTO watched_emails 
            (message_id, thread_id, subject, sender, date, snippet, state, discovered_at, updated_at, retry_count, last_error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            ''',
            (message_id, f"th_{message_id}", subject, sender, "2026-10-15", snippet, state, discovered_at, discovered_at, failure_reason)
        )
        if classification:
            cursor.execute("PRAGMA table_info(email_classifications)")
            has_summary_col = "summary" in [col[1] for col in cursor.fetchall()]
            if has_summary_col:
                cursor.execute(
                    '''
                    INSERT INTO email_classifications
                    (message_id, classification, risk_level, reasons, requires_human_review, processed_at, status, failure_reason, summary)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        message_id,
                        classification,
                        risk_level or "LOW",
                        json.dumps(reasons or ["Test explanation"]),
                        1 if requires_human_review else 0,
                        processed_at,
                        "SUCCESS" if not failure_reason else "FAILED",
                        failure_reason,
                        summary
                    )
                )
            else:
                cursor.execute(
                    '''
                    INSERT INTO email_classifications
                    (message_id, classification, risk_level, reasons, requires_human_review, processed_at, status, failure_reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        message_id,
                        classification,
                        risk_level or "LOW",
                        json.dumps(reasons or ["Test explanation"]),
                        1 if requires_human_review else 0,
                        processed_at,
                        "SUCCESS" if not failure_reason else "FAILED",
                        failure_reason
                    )
                )
        conn.commit()


def test_email_summary_empty_db(tmp_path):
    """1. Summary endpoint returns all zeros cleanly when database is empty or does not exist."""
    db_file = str(tmp_path / "nonexistent.db")
    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        response = client.get("/api/emails/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["total_discovered"] == 0
        assert data["processed"] == 0
        assert data["classified_count"] == 0
        assert data["unprocessed_count"] == 0
        assert data["by_classification"]["SAFE"] == 0
        assert data["by_classification"]["SUSPICIOUS"] == 0
        assert data["by_classification"]["NEEDS_REVIEW"] == 0
        assert data["requires_human_review_count"] == 0


def test_email_summary_mixed_data(tmp_path):
    """2. Summary endpoint aggregates states, classifications, and human-review counts accurately."""
    db_file = str(tmp_path / "emails.db")
    _init_test_email_db(db_file)

    # 1 Discovered (unprocessed)
    _insert_test_email(db_file, "msg_disc_01", "New Inquiry", "client@corp.com", "DISCOVERED")
    # 1 Processing (unprocessed)
    _insert_test_email(db_file, "msg_proc_01", "Checking Details", "vendor@corp.com", "PROCESSING")
    # 1 Failed (unprocessed)
    _insert_test_email(db_file, "msg_fail_01", "Server Alert", "monitoring@corp.com", "FAILED", failure_reason="Timeout")

    # 3 Processed with different classifications
    _insert_test_email(
        db_file, "msg_safe_01", "Weekly Standup", "alice@corp.com", "PROCESSED",
        classification="SAFE", risk_level="LOW", requires_human_review=False
    )
    _insert_test_email(
        db_file, "msg_susp_01", "Wire Funds Now", "hacker@evil.com", "PROCESSED",
        classification="SUSPICIOUS", risk_level="HIGH", requires_human_review=True
    )
    _insert_test_email(
        db_file, "msg_rev_01", "Policy Query", "compliance@corp.com", "PROCESSED",
        classification="NEEDS_REVIEW", risk_level="MEDIUM", requires_human_review=True
    )

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        response = client.get("/api/emails/summary")
        assert response.status_code == 200
        data = response.json()

        assert data["total_discovered"] == 6
        assert data["processed"] == 3
        assert data["processing"] == 1
        assert data["discovered"] == 1
        assert data["failed"] == 1
        assert data["unprocessed_count"] == 3  # discovered (1) + processing (1) + failed (1)
        assert data["classified_count"] == 3

        assert data["by_classification"]["SAFE"] == 1
        assert data["by_classification"]["SUSPICIOUS"] == 1
        assert data["by_classification"]["NEEDS_REVIEW"] == 1

        assert data["by_risk_level"]["LOW"] == 1
        assert data["by_risk_level"]["MEDIUM"] == 1
        assert data["by_risk_level"]["HIGH"] == 1

        assert data["requires_human_review_count"] == 2


def test_email_list_classification_and_risk_filtering(tmp_path):
    """3. List endpoint filters accurately by classification and risk level."""
    db_file = str(tmp_path / "emails.db")
    _init_test_email_db(db_file)

    _insert_test_email(db_file, "msg_01", "Safe Note", "a@corp.com", "PROCESSED", classification="SAFE", risk_level="LOW")
    _insert_test_email(db_file, "msg_02", "Phishing Alert", "b@corp.com", "PROCESSED", classification="SUSPICIOUS", risk_level="HIGH")
    _insert_test_email(db_file, "msg_03", "Pending Email", "c@corp.com", "DISCOVERED")

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        # Filter SAFE
        res_safe = client.get("/api/emails?classification=SAFE")
        assert res_safe.status_code == 200
        data_safe = res_safe.json()
        assert data_safe["total"] == 1
        assert data_safe["items"][0]["message_id"] == "msg_01"

        # Filter SUSPICIOUS
        res_susp = client.get("/api/emails?classification=SUSPICIOUS")
        assert res_susp.status_code == 200
        data_susp = res_susp.json()
        assert data_susp["total"] == 1
        assert data_susp["items"][0]["message_id"] == "msg_02"

        # Filter UNCLASSIFIED
        res_unclass = client.get("/api/emails?classification=UNCLASSIFIED")
        assert res_unclass.status_code == 200
        data_unclass = res_unclass.json()
        assert data_unclass["total"] == 1
        assert data_unclass["items"][0]["message_id"] == "msg_03"

        # Filter HIGH risk
        res_high = client.get("/api/emails?risk_level=HIGH")
        assert res_high.status_code == 200
        data_high = res_high.json()
        assert data_high["total"] == 1
        assert data_high["items"][0]["message_id"] == "msg_02"


def test_email_list_human_review_filtering(tmp_path):
    """4. List endpoint filters accurately by human-review requirement."""
    db_file = str(tmp_path / "emails.db")
    _init_test_email_db(db_file)

    _insert_test_email(db_file, "msg_auto", "Automated Notice", "bot@corp.com", "PROCESSED", classification="SAFE", requires_human_review=False)
    _insert_test_email(db_file, "msg_manual", "Suspicious Tool Command", "ext@corp.com", "PROCESSED", classification="SUSPICIOUS", requires_human_review=True)

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        res_req = client.get("/api/emails?requires_human_review=true")
        assert res_req.status_code == 200
        items_req = res_req.json()["items"]
        assert len(items_req) == 1
        assert items_req[0]["message_id"] == "msg_manual"
        assert items_req[0]["requires_human_review"] is True

        res_no_req = client.get("/api/emails?requires_human_review=false")
        assert res_no_req.status_code == 200
        items_no_req = res_no_req.json()["items"]
        assert len(items_no_req) == 1
        assert items_no_req[0]["message_id"] == "msg_auto"
        assert items_no_req[0]["requires_human_review"] is False


def test_email_list_pagination_and_invalid_parameters(tmp_path):
    """5. Validates pagination bounds and parameter validation."""
    db_file = str(tmp_path / "emails.db")
    _init_test_email_db(db_file)

    for i in range(5):
        _insert_test_email(
            db_file, f"msg_p_{i}", f"Subject {i}", f"sender_{i}@corp.com", "PROCESSED",
            classification="SAFE", discovered_at=f"2026-10-15T10:0{i}:00Z"
        )

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        # Page 1 with page_size=2
        res1 = client.get("/api/emails?page=1&page_size=2")
        assert res1.status_code == 200
        data1 = res1.json()
        assert data1["total"] == 5
        assert data1["page"] == 1
        assert data1["page_size"] == 2
        assert data1["total_pages"] == 3
        assert len(data1["items"]) == 2

        # Page 3 with page_size=2 (remaining 1 item)
        res3 = client.get("/api/emails?page=3&page_size=2")
        assert res3.status_code == 200
        data3 = res3.json()
        assert len(data3["items"]) == 1

        # Search parameter
        res_search = client.get("/api/emails?search=Subject 3")
        assert res_search.status_code == 200
        assert res_search.json()["total"] == 1
        assert res_search.json()["items"][0]["subject"] == "Subject 3"

        # Invalid classification
        res_bad_cls = client.get("/api/emails?classification=MALICIOUS")
        assert res_bad_cls.status_code == 400
        assert "Invalid classification filter" in res_bad_cls.json()["detail"]

        # Invalid risk
        res_bad_risk = client.get("/api/emails?risk_level=CRITICAL")
        assert res_bad_risk.status_code == 400
        assert "Invalid risk_level filter" in res_bad_risk.json()["detail"]

        # Invalid state
        res_bad_state = client.get("/api/emails?state=UNKNOWN")
        assert res_bad_state.status_code == 400
        assert "Invalid state filter" in res_bad_state.json()["detail"]

        # Invalid page (page=0 fails Pydantic ge=1 validation)
        res_bad_page = client.get("/api/emails?page=0")
        assert res_bad_page.status_code == 422


def test_email_detail_existing_and_nonexistent(tmp_path):
    """6. Detail lookup handles existing, nonexistent, and malformed IDs properly."""
    db_file = str(tmp_path / "emails.db")
    _init_test_email_db(db_file)

    _insert_test_email(
        db_file, "msg_valid_123", "Important Update", "director@corp.com", "PROCESSED",
        snippet="Snippet text here", classification="SUSPICIOUS", risk_level="HIGH",
        reasons=["Urgent request signature", "Mismatched domain"], requires_human_review=True
    )

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        # Existing email
        res = client.get("/api/emails/msg_valid_123")
        assert res.status_code == 200
        detail = res.json()
        assert detail["message_id"] == "msg_valid_123"
        assert detail["subject"] == "Important Update"
        assert detail["classification"] == "SUSPICIOUS"
        assert detail["risk_level"] == "HIGH"
        assert len(detail["reasons"]) == 2
        assert detail["requires_human_review"] is True

        # Nonexistent email
        res_404 = client.get("/api/emails/msg_does_not_exist")
        assert res_404.status_code == 404
        assert res_404.json()["detail"] == "Email not found."

        # Path traversal or malformed message ID
        res_malformed = client.get("/api/emails/..%2F..%2Fetc%2Fpasswd")
        assert res_malformed.status_code in (400, 404)


def test_email_detail_missing_classification_record(tmp_path):
    """7. Detail lookup handles emails discovered but not yet classified."""
    db_file = str(tmp_path / "emails.db")
    _init_test_email_db(db_file)

    # Email exists in watched_emails in DISCOVERED state, without row in email_classifications
    _insert_test_email(db_file, "msg_unclass_99", "Pending Ingestion", "bob@corp.com", "DISCOVERED")

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        res = client.get("/api/emails/msg_unclass_99")
        assert res.status_code == 200
        detail = res.json()
        assert detail["message_id"] == "msg_unclass_99"
        assert detail["state"] == "DISCOVERED"
        assert detail["classification"] is None
        assert detail["risk_level"] is None
        assert detail["reasons"] == []
        assert detail["requires_human_review"] is False


def test_email_database_errors_handled_safely(tmp_path):
    """8. Database errors and missing files are handled safely without exposing stack traces."""
    corrupt_file = str(tmp_path / "corrupt.db")
    with open(corrupt_file, "wb") as f:
        f.write(b"NOT A VALID SQLITE DATABASE FILE HEADER")

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": corrupt_file}):
        res_summary = client.get("/api/emails/summary")
        assert res_summary.status_code == 200
        assert res_summary.json()["total_discovered"] == 0

        res_list = client.get("/api/emails")
        assert res_list.status_code == 200
        assert res_list.json()["total"] == 0

        res_detail = client.get("/api/emails/msg_123")
        assert res_detail.status_code in (404, 500)


def test_no_sensitive_credentials_or_complete_bodies_exposed(tmp_path):
    """9. Endpoints never return OAuth secrets, tokens, or arbitrary full email bodies."""
    db_file = str(tmp_path / "emails.db")
    _init_test_email_db(db_file)

    _insert_test_email(
        db_file, "msg_clean_check", "Sensitive Discussion", "boss@corp.com", "PROCESSED",
        snippet="Short preview snippet text", classification="SAFE"
    )

    with patch.dict(os.environ, {
        "VETO_EMAIL_WATCHER_DB": db_file,
        "GOOGLE_OAUTH_CLIENT_SECRET": "secret_12345",
        "GOOGLE_OAUTH_REFRESH_TOKEN": "token_67890",
        "VETO_PROVENANCE_SECRET": "prov_sec_abcdef",
    }):
        res_list = client.get("/api/emails")
        text_list = res_list.text

        assert "secret_12345" not in text_list
        assert "token_67890" not in text_list
        assert "prov_sec_abcdef" not in text_list
        assert "body_data" not in text_list

        res_detail = client.get("/api/emails/msg_clean_check")
        text_detail = res_detail.text

        assert "secret_12345" not in text_detail
        assert "token_67890" not in text_detail
        assert "prov_sec_abcdef" not in text_detail
        assert "body_data" not in text_detail


def test_api_returns_persisted_summary(tmp_path):
    """10. Endpoint returns persisted natural language email summary for list and detail views."""
    db_file = str(tmp_path / "emails_with_summary.db")
    _init_test_email_db(db_file, with_summary_col=True)

    summary_text = "Action item: Approve budget request by 5 PM Friday."
    _insert_test_email(
        db_file,
        "msg_sum_1",
        "Budget Request",
        "finance@corp.com",
        "PROCESSED",
        classification="SAFE",
        risk_level="LOW",
        reasons=["Routine finance request", "Internal sender verified"],
        requires_human_review=False,
        summary=summary_text,
    )

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        # Check detail endpoint
        res = client.get("/api/emails/msg_sum_1")
        assert res.status_code == 200
        data = res.json()
        assert data["message_id"] == "msg_sum_1"
        assert data["summary"] == summary_text
        assert data["classification"] == "SAFE"
        assert data["risk_level"] == "LOW"
        assert data["requires_human_review"] is False
        assert len(data["reasons"]) == 2

        # Check list endpoint
        res_list = client.get("/api/emails")
        assert res_list.status_code == 200
        list_data = res_list.json()
        assert list_data["total"] == 1
        item = list_data["items"][0]
        assert item["message_id"] == "msg_sum_1"
        assert item["summary"] == summary_text


def test_api_null_and_missing_summary(tmp_path):
    """11. Endpoint gracefully returns None for NULL or unclassified email summaries."""
    db_file = str(tmp_path / "emails_null_summary.db")
    _init_test_email_db(db_file, with_summary_col=True)

    # Processed email with NULL summary (e.g. LLM failure during summary generation)
    _insert_test_email(
        db_file,
        "msg_proc_no_sum",
        "Urgent Notice",
        "alert@corp.com",
        "PROCESSED",
        classification="SUSPICIOUS",
        risk_level="HIGH",
        reasons=["Flagged phishing indicator"],
        requires_human_review=True,
        summary=None,
    )
    # Discovered email without any classification record
    _insert_test_email(
        db_file,
        "msg_disc_no_class",
        "Pending Email",
        "client@corp.com",
        "DISCOVERED",
    )

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        # Check processed email with NULL summary
        res1 = client.get("/api/emails/msg_proc_no_sum")
        assert res1.status_code == 200
        data1 = res1.json()
        assert data1["summary"] is None
        assert data1["classification"] == "SUSPICIOUS"
        assert data1["risk_level"] == "HIGH"
        assert data1["requires_human_review"] is True

        # Check unclassified email
        res2 = client.get("/api/emails/msg_disc_no_class")
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["summary"] is None
        assert data2["classification"] is None

        # Check list view
        res_list = client.get("/api/emails")
        assert res_list.status_code == 200
        items = res_list.json()["items"]
        assert len(items) == 2
        for it in items:
            assert it["summary"] is None


def test_api_backward_compatibility_schema_without_summary_column(tmp_path):
    """12. Backward compatibility: older databases without 'summary' column load seamlessly."""
    db_file = str(tmp_path / "older_schema.db")
    # Explicitly create schema WITHOUT summary column
    _init_test_email_db(db_file, with_summary_col=False)

    _insert_test_email(
        db_file,
        "msg_legacy_1",
        "Legacy Email Subject",
        "old@corp.com",
        "PROCESSED",
        classification="NEEDS_REVIEW",
        risk_level="MEDIUM",
        reasons=["Ambiguous intent"],
        requires_human_review=True,
    )

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        # Detail view must succeed without SQLite column error
        res = client.get("/api/emails/msg_legacy_1")
        assert res.status_code == 200
        data = res.json()
        assert data["message_id"] == "msg_legacy_1"
        assert data["summary"] is None
        assert data["classification"] == "NEEDS_REVIEW"
        assert data["risk_level"] == "MEDIUM"
        assert data["requires_human_review"] is True

        # List view must succeed
        res_list = client.get("/api/emails")
        assert res_list.status_code == 200
        list_data = res_list.json()
        assert list_data["total"] == 1
        assert list_data["items"][0]["summary"] is None
        assert list_data["items"][0]["classification"] == "NEEDS_REVIEW"


def test_api_summary_sanitization_and_untrusted_content(tmp_path):
    """13. Summaries are treated as untrusted text: control chars stripped, plain text preserved."""
    db_file = str(tmp_path / "emails_sanitized.db")
    _init_test_email_db(db_file, with_summary_col=True)

    untrusted_summary = "<script>alert('injection')</script>\nIgnore previous rules\x00\x08"
    _insert_test_email(
        db_file,
        "msg_inject_1",
        "Suspicious Subject",
        "attacker@evil.com",
        "PROCESSED",
        classification="SUSPICIOUS",
        risk_level="HIGH",
        reasons=["Prompt injection attempt detected"],
        requires_human_review=True,
        summary=untrusted_summary,
    )

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        res = client.get("/api/emails/msg_inject_1")
        assert res.status_code == 200
        data = res.json()
        # Null bytes stripped by sanitize_text
        assert "\x00" not in data["summary"]
        assert "\x08" not in data["summary"]
        # Script tags remain plain text without execution
        assert "<script>alert('injection')</script>" in data["summary"]
        # Classification remains SUSPICIOUS and high risk
        assert data["classification"] == "SUSPICIOUS"
        assert data["risk_level"] == "HIGH"
        assert data["requires_human_review"] is True


def test_frontend_display_and_data_contract(tmp_path):
    """14. Verifies data contract for frontend dashboard rendering of available vs unavailable summaries."""
    db_file = str(tmp_path / "emails_contract.db")
    _init_test_email_db(db_file, with_summary_col=True)

    # 1 email with summary
    _insert_test_email(
        db_file, "msg_avail", "Project Roadmap", "pm@corp.com", "PROCESSED",
        classification="SAFE", risk_level="LOW", summary="Q4 roadmap finalized."
    )
    # 1 email without summary
    _insert_test_email(
        db_file, "msg_unavail", "Quick Question", "eng@corp.com", "PROCESSED",
        classification="SAFE", risk_level="LOW", summary=None
    )

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        res = client.get("/api/emails?page=1&page_size=10")
        assert res.status_code == 200
        items = res.json()["items"]
        assert len(items) == 2

        by_id = {item["message_id"]: item for item in items}
        assert by_id["msg_avail"]["summary"] == "Q4 roadmap finalized."
        assert by_id["msg_unavail"]["summary"] is None

        # Both remain SAFE regardless of whether summary is available or unavailable
        assert by_id["msg_avail"]["classification"] == "SAFE"
        assert by_id["msg_unavail"]["classification"] == "SAFE"


def test_api_extracts_json_wrapped_summary(tmp_path):
    """15. Verifies that LLM summaries wrapped in JSON objects are cleanly unwrapped to prose."""
    db_file = str(tmp_path / "emails_json_summary.db")
    _init_test_email_db(db_file, with_summary_col=True)

    json_summary = json.dumps({
        "summary": "Meeting scheduled for Tuesday at 10 AM to discuss Q3 security metrics.",
        "risk": "low"
    })

    _insert_test_email(
        db_file,
        "msg_json_wrap",
        "Team Sync",
        "lead@corp.com",
        "PROCESSED",
        classification="SAFE",
        risk_level="LOW",
        summary=json_summary
    )

    with patch.dict(os.environ, {"VETO_EMAIL_WATCHER_DB": db_file}):
        res = client.get("/api/emails/msg_json_wrap")
        assert res.status_code == 200
        data = res.json()
        assert data["summary"] == "Meeting scheduled for Tuesday at 10 AM to discuss Q3 security metrics."
