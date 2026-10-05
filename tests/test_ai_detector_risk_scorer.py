"""
Unit tests for mini.ai_detector.risk_scorer module.
"""

from ai_detector.risk_scorer import RiskEngine
from ai_detector.schemas import RiskLevel
from ai_detector.config import (
    WEIGHT_ML,
    PENALTY_AUTH_FAIL,
    PENALTY_IP_URL,
    PENALTY_ANCHOR_MISMATCH,
    PENALTY_DEFANGED,
    OVERRIDE_FLOOR_MIME_MISMATCH,
    OVERRIDE_FLOOR_PHISH_TRIPWIRE,
)


def test_risk_engine_low_risk():
    engine = RiskEngine()
    features = {
        "spf_pass": 1.0,
        "dkim_pass": 1.0,
        "dmarc_pass": 1.0,
        "ip_literal_count": 0.0,
        "mismatched_anchor_count": 0.0,
        "defanged_url_count": 0.0,
        "mime_mismatch_detected": 0.0,
    }
    score, level, factors = engine.evaluate(confidence=0.10, features=features)

    assert score == round(WEIGHT_ML * 0.10, 2)  # 6.5
    assert level == RiskLevel.LOW
    assert len(factors) == 0


def test_risk_engine_medium_risk():
    engine = RiskEngine()
    features = {
        "spf_pass": 0.0,
        "dmarc_pass": 0.0,
        "ip_literal_count": 0.0,
        "mismatched_anchor_count": 0.0,
        "defanged_url_count": 0.0,
    }
    score, level, factors = engine.evaluate(confidence=0.40, features=features)

    # 65.0 * 0.40 + 15.0 = 26.0 + 15.0 = 41.0
    assert score == 41.0
    assert level == RiskLevel.MEDIUM
    assert "Failed SPF and DMARC alignment" in factors


def test_risk_engine_high_risk():
    engine = RiskEngine()
    features = {
        "spf_pass": 0.0,
        "dmarc_pass": 0.0,
        "ip_literal_count": 1.0,
        "defanged_url_count": 1.0,
    }
    # penalties: 15.0 (auth) + 12.0 (ip) + 10.0 (defanged) = 37.0
    # ml: 65.0 * 0.50 = 32.5
    # total = 69.5
    score, level, factors = engine.evaluate(confidence=0.50, features=features)

    assert score == 69.5
    assert level == RiskLevel.HIGH
    assert len(factors) == 3


def test_risk_engine_critical_mime_override():
    engine = RiskEngine()
    features = {
        "spf_pass": 1.0,
        "dmarc_pass": 1.0,
        "mime_mismatch_detected": 1.0,
    }
    score, level, factors = engine.evaluate(confidence=0.10, features=features)

    # Floor override: 85.0
    assert score == OVERRIDE_FLOOR_MIME_MISMATCH  # 85.0
    assert level == RiskLevel.CRITICAL
    assert "CRITICAL: Attachment magic bytes mismatch detected (disguised payload)" in factors


def test_risk_engine_critical_phish_tripwire_override():
    engine = RiskEngine()
    features = {
        "spf_pass": 0.0,
        "dmarc_pass": 0.0,
        "mismatched_anchor_count": 1.0,
    }
    score, level, factors = engine.evaluate(confidence=0.20, features=features)

    # Floor override: 80.0
    assert score >= OVERRIDE_FLOOR_PHISH_TRIPWIRE  # 80.0
    assert level == RiskLevel.CRITICAL
    assert "CRITICAL: Deceptive hyperlink combined with unauthenticated domain origin" in factors


def test_risk_engine_none_features():
    engine = RiskEngine()
    score, level, factors = engine.evaluate(confidence=0.0, features=None)

    # Missing/empty features defaults spf_pass=0 and dmarc_pass=0 -> PENALTY_AUTH_FAIL (15.0)
    assert score == PENALTY_AUTH_FAIL  # 15.0
    assert level == RiskLevel.LOW
    assert "Failed SPF and DMARC alignment" in factors
