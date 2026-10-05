"""
Unit tests for mini.ai_detector.predictor module.
"""

from ai_detector.predictor import EmailAIDetector
from ai_detector.schemas import DetectionOutput, RiskLevel
from email_parser.schemas import (
    ParsedEmailResult,
    HeaderData,
    AuthResults,
    ExtractedURL,
    AttachmentMetadata,
)


def test_email_ai_detector_initialization():
    detector = EmailAIDetector()
    assert detector.model is not None
    assert detector.metadata is not None
    assert detector.metadata["n_features"] == 16


def test_email_ai_detector_predict_clean_email():
    detector = EmailAIDetector()
    headers = HeaderData(
        subject="Weekly Project Status Update",
        auth_results=AuthResults(spf_result="pass", dkim_result="pass", dmarc_result="pass"),
    )
    parsed = ParsedEmailResult(
        headers=headers,
        body_text="Hi team, here is the status update for this week. All tasks are on schedule.",
    )

    output = detector.predict(parsed)

    assert isinstance(output, DetectionOutput)
    assert output.is_threat is False
    assert output.risk_level == RiskLevel.LOW
    assert output.confidence_score < 0.50
    assert output.risk_score < 35.0
    assert output.inference_time_ms >= 0.0


def test_email_ai_detector_predict_phishing_email():
    detector = EmailAIDetector()
    headers = HeaderData(
        subject="URGENT: Password Reset & Verify Account Immediately",
        auth_results=AuthResults(spf_result="fail", dkim_result="fail", dmarc_result="fail"),
    )
    urls = [
        ExtractedURL(
            url="http://phishing-site.ru/login",
            anchor_text="http://paypal.com",
            domain="phishing-site.ru",
        ),
        ExtractedURL(url="http://192.168.1.1/admin", is_ip_address=True),
    ]
    attachments = [
        AttachmentMetadata(filename="invoice.pdf.exe", content_type_mismatch=True)
    ]
    parsed = ParsedEmailResult(
        headers=headers,
        body_text="PLEASE RESET YOUR PASSWORD IMMEDIATELY. URGENT WIRE TRANSFER REQUIRED.",
        urls=urls,
        attachments=attachments,
    )

    output = detector.predict(parsed)

    assert isinstance(output, DetectionOutput)
    assert output.is_threat is True
    assert output.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert output.confidence_score >= 0.50
    assert output.risk_score >= 60.0
    assert len(output.contributing_factors) > 0


def test_email_ai_detector_predict_none_input():
    detector = EmailAIDetector()
    output = detector.predict(None)

    assert isinstance(output, DetectionOutput)
    assert output.inference_time_ms >= 0.0
    assert output.feature_vector_summary["body_char_count"] == 0.0
