
"""Local-development Gmail OAuth and read-only message retrieval."""
import os
if os.getenv("SHIELDMAIL_ENV") == "development":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
import base64
import json
import secrets
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from flask import Blueprint, current_app, jsonify, redirect, request, session, url_for
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from integration.pipeline import ShieldMailPipeline

gmail_oauth = Blueprint("gmail_oauth", __name__)
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLIENT_FILE = Path(
    os.getenv("GOOGLE_OAUTH_CLIENT_FILE", str(PROJECT_ROOT / "oauth_client.json"))
)
TOKEN_DB = PROJECT_ROOT / "instance" / "gmail_tokens.sqlite3"

# Reuse the existing scanner, rather than creating a new model per request.
pipeline = ShieldMailPipeline()


def _db():
    TOKEN_DB.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(TOKEN_DB)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS gmail_tokens (
            session_id TEXT PRIMARY KEY,
            token_json TEXT NOT NULL
        )
    """)
    return connection


def _ensure_scan_history_table():
    with _db() as connection:
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


def _save_scan_result(message_id, result):
    assessment = (
        result.get("risk_assessment", {})
        if isinstance(result, dict)
        else {}
    )

    if not isinstance(assessment, dict):
        assessment = {}

    risk_level = assessment.get("risk_level", "UNKNOWN")
    risk_score = assessment.get("risk_score", "N/A")
    action = assessment.get("recommended_action", "UNKNOWN")
    scanned_at = datetime.now(timezone.utc).isoformat()

    _ensure_scan_history_table()

    with _db() as connection:
        connection.execute("""
            INSERT INTO gmail_scan_results (
                session_id, message_id, risk_level, risk_score,
                recommended_action, scanned_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id, message_id) DO UPDATE SET
                risk_level = excluded.risk_level,
                risk_score = excluded.risk_score,
                recommended_action = excluded.recommended_action,
                scanned_at = excluded.scanned_at
        """, (
            _session_id(),
            message_id,
            str(risk_level),
            str(risk_score),
            str(action),
            scanned_at,
        ))



def _session_id():
    if "gmail_session_id" not in session:
        session["gmail_session_id"] = secrets.token_urlsafe(32)
    return session["gmail_session_id"]


def _make_flow(state=None):
    if not CLIENT_FILE.is_file():
        raise FileNotFoundError(
            f"OAuth client file not found: {CLIENT_FILE}"
        )

    return Flow.from_client_secrets_file(
        str(CLIENT_FILE),
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for(
            "gmail_oauth.oauth_callback", _external=True
        ),
    )


def _save_credentials(credentials):
    with _db() as connection:
        connection.execute(
            """INSERT INTO gmail_tokens(session_id, token_json)
               VALUES (?, ?)
               ON CONFLICT(session_id)
               DO UPDATE SET token_json = excluded.token_json""",
            (_session_id(), credentials.to_json()),
        )


def _get_credentials():
    with _db() as connection:
        row = connection.execute(
            "SELECT token_json FROM gmail_tokens WHERE session_id = ?",
            (_session_id(),),
        ).fetchone()

    if not row:
        return None

    credentials = Credentials.from_authorized_user_info(
        json.loads(row[0]), SCOPES
    )

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(GoogleRequest())
        _save_credentials(credentials)

    if not credentials.valid:
        return None

    return credentials


def _gmail_service():
    credentials = _get_credentials()
    if credentials is None:
        return None

    return build(
        "gmail", "v1", credentials=credentials,
        cache_discovery=False,
    )


@gmail_oauth.get("/oauth/login")
def oauth_login():
    flow = _make_flow()
    authorization_url, state = flow.authorization_url(
    access_type="offline",
    include_granted_scopes="true",
    prompt="consent",
)

    session["gmail_oauth_state"] = state
    session["gmail_code_verifier"] = flow.code_verifier
    return redirect(authorization_url)


@gmail_oauth.get("/oauth/callback")
def oauth_callback():
    expected_state = session.pop("gmail_oauth_state", None)
    returned_state = request.args.get("state")

    if not expected_state or not returned_state or not secrets.compare_digest(
        expected_state, returned_state
    ):
        return jsonify({"error": "Invalid OAuth state. Please try again."}), 400

    if request.args.get("error"):
        return jsonify({
            "error": "Google authorization was not completed.",
            "details": request.args.get("error"),
        }), 400

    try:
        code_verifier = session.pop("gmail_code_verifier", None)

        if not code_verifier:
            return jsonify({
        "error": "OAuth session expired. Please start login again."
        }), 400

        flow = _make_flow(state=expected_state)
        flow.code_verifier = code_verifier
        flow.fetch_token(authorization_response=request.url)
        _save_credentials(flow.credentials)
        return jsonify({
            "status": "connected",
            "message": "Gmail connected. You can now retrieve messages.",
        })
    except Exception:
        current_app.logger.exception("Gmail OAuth callback failed")
        return jsonify({
            "error": "Gmail authorization failed. Check server logs."
        }), 500


@gmail_oauth.get("/gmail/messages")
def list_gmail_messages():
    try:
        service = _gmail_service()
        if service is None:
            return jsonify({
                "error": "Gmail is not connected.",
                "connect_url": "/oauth/login",
            }), 401

        result = service.users().messages().list(
            userId="me",
            maxResults=10,
        ).execute()

        return jsonify({
            "messages": result.get("messages", []),
            "result_size_estimate": result.get("resultSizeEstimate", 0),
        })
    except HttpError:
        current_app.logger.exception("Gmail message listing failed")
        return jsonify({"error": "Could not retrieve Gmail messages."}), 502


@gmail_oauth.post("/gmail/scan/<message_id>")
def scan_gmail_message(message_id):
    try:
        service = _gmail_service()
        if service is None:
            return jsonify({"error": "Gmail is not connected."}), 401

        message = service.users().messages().get(
            userId="me",
            id=message_id,
            format="raw",
        ).execute()

        raw = message.get("raw")
        if not raw:
            return jsonify({"error": "Gmail returned no raw message."}), 422

        padding = "=" * (-len(raw) % 4)
        raw_bytes = base64.urlsafe_b64decode(raw + padding)


        result = pipeline.analyze(raw_bytes)
        _save_scan_result(message_id, result)

        return jsonify({
        "message_id": message_id,
        "result": result,
        })
    except HttpError:
        current_app.logger.exception("Gmail message scan retrieval failed")
        return jsonify({"error": "Could not retrieve the requested email."}), 502
    except Exception:
        current_app.logger.exception("ShieldMail Gmail scan failed")
        return jsonify({"error": "Email scanning failed."}), 500


@gmail_oauth.get("/gmail/scan-history")
def gmail_scan_history():
    try:
        # Require an active Gmail connection for this browser session.
        if _gmail_service() is None:
            return jsonify({
                "error": "Gmail is not connected.",
                "connect_url": "/oauth/login",
            }), 401

        _ensure_scan_history_table()

        limit = request.args.get("limit", default=50, type=int)
        limit = max(1, min(limit or 50, 100))

        with _db() as connection:
            rows = connection.execute("""
                SELECT message_id, risk_level, risk_score,
                       recommended_action, scanned_at
                FROM gmail_scan_results
                WHERE session_id = ?
                ORDER BY scanned_at DESC
                LIMIT ?
            """, (_session_id(), limit)).fetchall()

        results = [
            {
                "message_id": row[0],
                "risk_level": row[1],
                "risk_score": row[2],
                "recommended_action": row[3],
                "scanned_at": row[4],
            }
            for row in rows
        ]

        return jsonify({
            "count": len(results),
            "results": results,
        })

    except Exception:
        current_app.logger.exception("Scan history retrieval failed")
        return jsonify({"error": "Could not retrieve scan history."}), 500


@gmail_oauth.get("/gmail/scan-history/<message_id>")
def gmail_scan_history_detail(message_id):
    try:
        if _gmail_service() is None:
            return jsonify({"error": "Gmail is not connected."}), 401

        _ensure_scan_history_table()

        with _db() as connection:
            row = connection.execute("""
                SELECT message_id, risk_level, risk_score,
                       recommended_action, scanned_at
                FROM gmail_scan_results
                WHERE session_id = ? AND message_id = ?
            """, (_session_id(), message_id)).fetchone()

        if row is None:
            return jsonify({"error": "No saved scan result found."}), 404

        return jsonify({
            "message_id": row[0],
            "risk_level": row[1],
            "risk_score": row[2],
            "recommended_action": row[3],
            "scanned_at": row[4],
        })

    except Exception:
        current_app.logger.exception("Scan history detail retrieval failed")
        return jsonify({"error": "Could not retrieve scan result."}), 500


@gmail_oauth.post("/oauth/disconnect")
def disconnect_gmail():
    with _db() as connection:
        connection.execute(
            "DELETE FROM gmail_tokens WHERE session_id = ?",
            (_session_id(),),
        )

    session.pop("gmail_session_id", None)
    session.pop("gmail_oauth_state", None)

    return jsonify({"status": "disconnected"})
