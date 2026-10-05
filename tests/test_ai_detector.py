"""
End-to-End Test Suite for AI Detection Subsystem.

Validates benign emails, credential phishing, safety override floors, malformed empty payloads,
and feature manifest alignment against EmailAIDetector.
"""

import json
from ai_detector import (
    EmailAIDetector,
    FeatureExtractor,
    RiskLevel,
    METADATA_FILE,
    FEATURE_NAMES,
)
from email_parser.schemas import (
    ParsedEmailResult,
    HeaderData,
    AuthResults,
    ExtractedURL,
    AttachmentMetadata,
)


def test_benign_email():
    """Validates that a legitimate, fully authenticated email receives a LOW risk assessment."""
    detector = EmailAIDetector()

    headers = HeaderData(
        subject="Monthly Engineering Team Sync Agenda",
        auth_results=AuthResults(spf_result="pass", dkim_result="pass", dmarc_result="pass"),
    )
    parsed = ParsedEmailResult(
        headers=headers,
        body_text="Hi team,\n\nHere is the proposed agenda for our monthly engineering sync. Please review the items before Thursday.\n\nBest regards,\nAlice",
        urls=[
            ExtractedURL(
                url="https://company.org/docs/agenda",
                domain="company.org",
                anchor_text="https://company.org/docs/agenda",
            )
        ],
    )

    result = detector.predict(parsed)

    assert result.is_threat is False
    assert result.risk_level == RiskLevel.LOW
    assert result.risk_score < 35.0


def test_credential_phishing():
    """Validates that a phishing payload with failed auth and suspicious indicators triggers HIGH/CRITICAL threat."""
    detector = EmailAIDetector()

    headers = HeaderData(
        subject="URGENT: Your account has been suspended due to unauthorized access",
        auth_results=AuthResults(spf_result="fail", dkim_result="none", dmarc_result="fail"),
    )
    urls = [
        ExtractedURL(
            url="http://192.168.1.50/verify_account",
            is_ip_address=True,
            anchor_text="http://security.bank.com/verify",
        ),
        ExtractedURL(
            url="hxxp://malicious-login[.]com",
            was_defanged=True,
        ),
    ]
    parsed = ParsedEmailResult(
        headers=headers,
        body_text="URGENT ACTION REQUIRED. Your account is suspended. Verify account immediately or payroll wire transfer will be locked.",
        urls=urls,
    )

    result = detector.predict(parsed)

    assert result.is_threat is True
    assert result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert result.confidence_score >= 0.50
    assert len(result.contributing_factors) > 0


def test_mime_mismatch_override():
    """Validates that attachment magic byte mismatch triggers CRITICAL floor override (score >= 85.0)."""
    detector = EmailAIDetector()

    headers = HeaderData(
        subject="Thank you for your inquiry",
        auth_results=AuthResults(spf_result="pass", dkim_result="pass", dmarc_result="pass"),
    )
    attachments = [
        AttachmentMetadata(
            filename="Receipt_2026.pdf.exe",
            content_type="application/pdf",
            content_type_mismatch=True,
        )
    ]
    parsed = ParsedEmailResult(
        headers=headers,
        body_text="Dear Valued Customer,\n\nPlease find attached the requested receipt PDF for your recent order.",
        attachments=attachments,
    )

    result = detector.predict(parsed)

    assert result.risk_score >= 85.0
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.is_threat is True

    # Verify CRITICAL override factor is recorded in factors list
    override_found = any(
        "magic bytes mismatch" in factor.lower() or "disguised payload" in factor.lower()
        for factor in result.contributing_factors
    )
    assert override_found is True


def test_malformed_empty_email():
    """Validates that empty or malformed inputs run safely without throwing exceptions."""
    detector = EmailAIDetector()

    parsed_empty = ParsedEmailResult()
    result_empty = detector.predict(parsed_empty)
    assert result_empty is not None
    assert result_empty.inference_time_ms >= 0.0

    result_none = detector.predict(None)
    assert result_none is not None
    assert result_none.inference_time_ms >= 0.0


def test_feature_manifest_alignment():
    """Validates feature vector length (16) and sequence alignment with feature_metadata.json."""
    detector = EmailAIDetector()

    # Extract feature vector
    extractor = FeatureExtractor()
    arr, feat_dict = extractor.extract_vector(ParsedEmailResult())

    assert len(arr) == 16
    assert list(feat_dict.keys()) == FEATURE_NAMES

    # Check model metadata file sequence alignment
    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["n_features"] == 16
    assert meta["feature_names"] == FEATURE_NAMES
    assert detector.metadata["feature_names"] == FEATURE_NAMES
