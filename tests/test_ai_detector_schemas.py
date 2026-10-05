"""
Unit tests for mini.ai_detector.schemas module.
"""

import pytest
from pydantic import ValidationError
from ai_detector.schemas import (
    RiskLevel,
    RiskFactor,
    DetectionOutput,
)


def test_risk_level_enum():
    assert RiskLevel.LOW == "LOW"
    assert RiskLevel.MEDIUM == "MEDIUM"
    assert RiskLevel.HIGH == "HIGH"
    assert RiskLevel.CRITICAL == "CRITICAL"
    assert set(RiskLevel.__members__.keys()) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_risk_factor_defaults_and_custom():
    factor = RiskFactor(
        rule_id="RULE_01",
        description="Failed auth checks",
        points_added=15.0,
    )
    assert factor.rule_id == "RULE_01"
    assert factor.description == "Failed auth checks"
    assert factor.points_added == 15.0
    assert factor.is_override is False

    override_factor = RiskFactor(
        rule_id="RULE_OVERRIDE",
        description="Magic byte mismatch",
        points_added=85.0,
        is_override=True,
    )
    assert override_factor.is_override is True


def test_detection_output_defaults_and_validation():
    output = DetectionOutput(
        is_threat=True,
        confidence_score=0.9254,
        risk_score=88.50,
        risk_level=RiskLevel.HIGH,
        contributing_factors=["SPF/DMARC auth failure", "Magic byte executable disguise"],
        feature_vector_summary={"spf_pass": 0.0, "mime_mismatch_detected": 1.0},
        inference_time_ms=12.4,
    )
    assert output.is_threat is True
    assert output.confidence_score == 0.9254
    assert output.risk_score == 88.50
    assert output.risk_level == RiskLevel.HIGH
    assert len(output.contributing_factors) == 2
    assert output.feature_vector_summary["mime_mismatch_detected"] == 1.0
    assert output.inference_time_ms == 12.4


def test_detection_output_bounds_validation():
    # Confidence score > 1.0 should raise ValidationError
    with pytest.raises(ValidationError):
        DetectionOutput(confidence_score=1.5)

    # Confidence score < 0.0 should raise ValidationError
    with pytest.raises(ValidationError):
        DetectionOutput(confidence_score=-0.1)

    # Risk score > 100.0 should raise ValidationError
    with pytest.raises(ValidationError):
        DetectionOutput(risk_score=105.0)

    # Risk score < 0.0 should raise ValidationError
    with pytest.raises(ValidationError):
        DetectionOutput(risk_score=-5.0)
