"""Conservative email-body versus PDF consistency checks."""

from io import BytesIO
import re
from typing import Any

from pypdf import PdfReader


MAX_PDF_BYTES = 10 * 1024 * 1024
MAX_PAGES = 10
MAX_TEXT_CHARS = 30_000

# These are broad categories, not a semantic or malware classifier.
CATEGORY_TERMS = {
    "receipt": (
        "receipt", "payment received", "payment confirmation",
        "transaction receipt", "fee paid",
    ),
    "invoice": (
        "invoice", "amount due", "bill to", "payment due",
    ),
    "resume": (
        "resume", "curriculum vitae", "work experience",
        "professional experience",
    ),
    "offer_letter": (
        "offer letter", "employment offer", "job offer",
        "joining date", "salary package",
    ),
    "bank_statement": (
        "bank statement", "account statement",
        "opening balance", "closing balance",
    ),
    "account_security": (
        "verify your account", "reset your password",
        "confirm your identity", "account suspended",
        "login credentials", "enter your password",
    ),
}


def _categories(text: str) -> set[str]:
    text = re.sub(r"\s+", " ", text.lower())
    found = set()

    for category, terms in CATEGORY_TERMS.items():
        if any(term in text for term in terms):
            found.add(category)

    return found


def _extract_pdf_text(data: bytes) -> str:
    if not data or len(data) > MAX_PDF_BYTES:
        return ""

    # Avoid attempting to parse arbitrary files as PDFs.
    if not data.startswith(b"%PDF-"):
        return ""

    try:
        reader = PdfReader(BytesIO(data), strict=True)

        if reader.is_encrypted:
            return ""

        parts = []
        for page in reader.pages[:MAX_PAGES]:
            text = page.extract_text()
            if text:
                parts.append(text)

            if sum(len(part) for part in parts) >= MAX_TEXT_CHARS:
                break

        return "\n".join(parts)[:MAX_TEXT_CHARS]

    except Exception:
        return ""


def analyze_attachment_consistency(
    body_text: str | None,
    attachments: list[Any],
) -> list[dict[str, str]]:
    """Return explainable findings for strong category mismatches."""
    if not body_text or not body_text.strip():
        return []

    body_categories = _categories(body_text)
    if not body_categories:
        return []

    findings = []

    for attachment in attachments:
        filename = getattr(attachment, "filename", "")
        content_type = getattr(attachment, "content_type", "")
        data = getattr(attachment, "data", b"")

        is_pdf = (
            content_type.lower().split(";")[0].strip() == "application/pdf"
            or filename.lower().endswith(".pdf")
        )
        if not is_pdf:
            continue

        pdf_text = _extract_pdf_text(data)
        if len(pdf_text.strip()) < 40:
            # Scanned, encrypted, unreadable, or unsupported PDFs are unknown.
            continue

        pdf_categories = _categories(pdf_text)
        if not pdf_categories:
            continue

        # Require a strong, mutually exclusive category conflict.
        exclusive_pairs = [
            ({"receipt"}, {"account_security"}),
            ({"invoice"}, {"account_security"}),
            ({"bank_statement"}, {"account_security"}),
            ({"resume"}, {"account_security"}),
            ({"offer_letter"}, {"account_security"}),
        ]

        mismatch = any(
            (body_categories & left and pdf_categories & right)
            or (body_categories & right and pdf_categories & left)
            for left, right in exclusive_pairs
        )

        if mismatch:
            findings.append({
                "type": "pdf_body_content_mismatch",
                "severity": "MEDIUM",
                "filename": filename or "unnamed.pdf",
                "reason": (
                    "The email and PDF contain conflicting content indicators: "
                    f"email categories={sorted(body_categories)}, "
                    f"PDF categories={sorted(pdf_categories)}."
                ),
            })

    return findings