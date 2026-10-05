"""
Unit tests for mini.ai_detector.config module.
"""

from pathlib import Path
from ai_detector.config import (
    BASE_DIR,
    MODEL_DIR,
    MODEL_FILE,
    METADATA_FILE,
    WEIGHT_ML,
    PENALTY_AUTH_FAIL,
    PENALTY_IP_URL,
    PENALTY_ANCHOR_MISMATCH,
    PENALTY_DEFANGED,
    OVERRIDE_FLOOR_MIME_MISMATCH,
    OVERRIDE_FLOOR_PHISH_TRIPWIRE,
    URGENCY_KEYWORDS,
    FEATURE_NAMES,
)


def test_paths_configuration():
    assert isinstance(BASE_DIR, Path)
    assert isinstance(MODEL_DIR, Path)
    assert MODEL_DIR == BASE_DIR / "models"
    assert MODEL_FILE == MODEL_DIR / "random_forest_v1.joblib"
    assert METADATA_FILE == MODEL_DIR / "feature_metadata.json"


def test_scoring_weights_and_constants():
    assert WEIGHT_ML == 65.0
    assert PENALTY_AUTH_FAIL == 15.0
    assert PENALTY_IP_URL == 12.0
    assert PENALTY_ANCHOR_MISMATCH == 18.0
    assert PENALTY_DEFANGED == 10.0
    assert OVERRIDE_FLOOR_MIME_MISMATCH == 85.0
    assert OVERRIDE_FLOOR_PHISH_TRIPWIRE == 80.0


def test_urgency_keywords():
    expected_keywords = [
        "urgent",
        "wire transfer",
        "suspended",
        "password reset",
        "verify account",
        "unauthorized",
        "immediately",
        "action required",
        "payroll",
        "tax refund",
        "security alert",
        "confirm identity",
        "billing issue",
    ]
    assert URGENCY_KEYWORDS == expected_keywords
    assert len(URGENCY_KEYWORDS) == 13


def test_feature_manifest():
    expected_features = [
        "spf_pass",
        "dkim_pass",
        "dmarc_pass",
        "hop_count",
        "max_hop_delay_sec",
        "body_char_count",
        "body_entropy",
        "uppercase_ratio",
        "urgency_word_count",
        "html_to_text_ratio",
        "url_count",
        "ip_literal_count",
        "defanged_url_count",
        "mismatched_anchor_count",
        "attachment_count",
        "mime_mismatch_detected",
    ]
    assert FEATURE_NAMES == expected_features
    assert len(FEATURE_NAMES) == 16
