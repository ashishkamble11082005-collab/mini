"""Focused regression tests for ShieldMail AI detector v2 integration."""

from ai_detector.config import FEATURE_NAMES, METADATA_FILE, MODEL_FILE
from ai_detector.predictor import EmailAIDetector, _normalize_authentication
from email_parser.schemas import AuthResults, HeaderData, ParsedEmailResult


def test_nested_shieldmail_authentication_is_normalized():
    result = _normalize_authentication({
        "spf": {"status": "FAIL"},
        "dkim": {"status": "PASS"},
        "dmarc": {"status": "FAIL"},
    })
    assert result is not None
    assert result.spf_result == "FAIL"
    assert result.dkim_result == "PASS"
    assert result.dmarc_result == "FAIL"


def test_v2_artifacts_and_feature_manifest_match():
    assert len(FEATURE_NAMES) == 22
    assert MODEL_FILE.is_file()
    assert METADATA_FILE.is_file()
    detector = EmailAIDetector()
    assert detector.model.n_features_in_ == len(FEATURE_NAMES)


def test_verified_authentication_overrides_email_header_authentication():
    detector = EmailAIDetector()
    parsed = ParsedEmailResult(
        headers=HeaderData(
            subject="Urgent verify account",
            auth_results=AuthResults(
                spf_result="PASS", dkim_result="PASS", dmarc_result="PASS"
            ),
        ),
        body_text="Please verify account immediately.",
    )
    result = detector.predict(parsed, {
        "spf": {"status": "FAIL"},
        "dkim": {"status": "PASS"},
        "dmarc": {"status": "FAIL"},
    })
    assert result.feature_vector_summary["spf_fail"] == 1.0
    assert result.feature_vector_summary["dmarc_fail"] == 1.0
    assert result.feature_vector_summary["spf_pass"] == 0.0
    assert result.feature_vector_summary["dmarc_pass"] == 0.0
