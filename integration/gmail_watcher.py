
"""Opt-in periodic Gmail scanner with persistent scan history."""

import base64
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone

from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from integration.gmail_oauth import TOKEN_DB
from integration.pipeline import ShieldMailPipeline

logger = logging.getLogger(__name__)

POLL_SECONDS = 60
MAX_RESULTS_PER_POLL = 100
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

pipeline = ShieldMailPipeline()
stop_event = threading.Event()


def initialize_database():
    """Create persistent scan history without modifying OAuth tokens."""
    with sqlite3.connect(TOKEN_DB, timeout=30) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS gmail_scan_results (
                session_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                PRIMARY KEY (session_id, message_id)
            )
        """)
        connection.commit()


def already_scanned(session_id, message_id):
    """Check whether this message has a saved result."""
    with sqlite3.connect(TOKEN_DB, timeout=30) as connection:
        row = connection.execute(
            """
            SELECT 1 FROM gmail_scan_results
            WHERE session_id = ? AND message_id = ?
            """,
            (session_id, message_id),
        ).fetchone()

    return row is not None


def save_result(session_id, message_id, risk_level, risk_score, action):
    """Save one completed scan. The primary key prevents duplicates."""
    scanned_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(TOKEN_DB, timeout=30) as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO gmail_scan_results
            (session_id, message_id, risk_level, risk_score,
             recommended_action, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                message_id,
                str(risk_level),
                str(risk_score),
                str(action),
                scanned_at,
            ),
        )
        connection.commit()


def get_credentials(session_id, token_json):
    """Load credentials and persist refreshed OAuth tokens."""
    credentials = Credentials.from_authorized_user_info(
        json.loads(token_json), SCOPES
    )

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(GoogleRequest())

        with sqlite3.connect(TOKEN_DB, timeout=30) as connection:
            connection.execute(
                """
                UPDATE gmail_tokens
                SET token_json = ?
                WHERE session_id = ?
                """,
                (credentials.to_json(), session_id),
            )
            connection.commit()

    if not credentials.valid:
        logger.warning("Skipping account with invalid OAuth credentials.")
        return None

    return credentials


def scan_account(session_id, token_json):
    """Scan recent inbox messages for one stored OAuth session."""
    credentials = get_credentials(session_id, token_json)
    if credentials is None:
        return

    service = build(
        "gmail",
        "v1",
        credentials=credentials,
        cache_discovery=False,
    )

    # This prototype checks the latest 100 inbox messages per polling cycle.
    response = service.users().messages().list(
        userId="me",
        labelIds=["INBOX"],
        maxResults=MAX_RESULTS_PER_POLL,
    ).execute()

    messages = response.get("messages", [])
    scanned_count = 0
    skipped_count = 0

    for item in messages:
        if stop_event.is_set():
            break

        message_id = item["id"]

        if already_scanned(session_id, message_id):
            skipped_count += 1
            continue

        message = service.users().messages().get(
            userId="me",
            id=message_id,
            format="raw",
        ).execute()

        raw = message.get("raw")
        if not raw:
            logger.warning("Gmail message had no raw content; skipping.")
            continue

        padding = "=" * (-len(raw) % 4)
        raw_bytes = base64.urlsafe_b64decode(raw + padding)

        result = pipeline.analyze(raw_bytes)
        if not isinstance(result, dict):
            logger.warning("Pipeline returned an unexpected result type.")
            continue

        assessment = result.get("risk_assessment", {})
        if not isinstance(assessment, dict):
            logger.warning("Pipeline result has no valid risk assessment.")
            continue

        risk_level = assessment.get("risk_level", "UNKNOWN")
        risk_score = assessment.get("risk_score", "N/A")
        action = assessment.get("recommended_action", "UNKNOWN")

        save_result(
            session_id,
            message_id,
            risk_level,
            risk_score,
            action,
        )

        logger.info(
            "Gmail scan complete: risk=%s, score=%s, action=%s",
            risk_level,
            risk_score,
            action,
        )
        scanned_count += 1

    logger.info(
        "Account scan finished: new_scans=%s, already_scanned=%s",
        scanned_count,
        skipped_count,
    )


def run_worker():
    """Poll stored OAuth sessions until the worker is stopped."""
    initialize_database()
    logger.info(
        "ShieldMail Gmail watcher started; interval=%ss",
        POLL_SECONDS,
    )

    while not stop_event.is_set():
        try:
            with sqlite3.connect(TOKEN_DB, timeout=30) as connection:
                rows = connection.execute(
                    "SELECT session_id, token_json FROM gmail_tokens"
                ).fetchall()

            for session_id, token_json in rows:
                if stop_event.is_set():
                    break

                try:
                    scan_account(session_id, token_json)
                except HttpError as exc:
                    # Do not print the full response, which may contain details.
                    logger.error(
                        "Gmail API request failed with HTTP status %s.",
                        getattr(exc.resp, "status", "unknown"),
                    )
                except Exception:
                    logger.exception("Failed to scan a connected Gmail account.")

        except Exception:
            logger.exception("Gmail watcher iteration failed.")

        stop_event.wait(POLL_SECONDS)


if __name__ == "__main__":
    if os.getenv("SHIELDMAIL_GMAIL_WATCHER_ENABLED") != "1":
        raise SystemExit(
            "Set SHIELDMAIL_GMAIL_WATCHER_ENABLED=1 to enable the watcher."
        )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        run_worker()
    except KeyboardInterrupt:
        stop_event.set()
        logger.info("ShieldMail Gmail watcher stopped.")
