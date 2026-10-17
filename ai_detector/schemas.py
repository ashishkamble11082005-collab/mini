"""
Pydantic v2 Schemas and Data Contracts for AI Detection Subsystem.

Defines RiskLevel enum, RiskFactor model, and DetectionOutput output contract.

Notice: The AI detection model is trained and evaluated on synthetic/simulated datasets.
Reported ROC-AUC and evaluation metrics reflect synthetic test performance only and
must not be cited as verified real-world baseline performance.
"""

from enum import Enum
from pydantic import BaseModel, Field, ConfigDict  # type: ignore # pyrefly: ignore [missing-import]


class RiskLevel(str, Enum):
    """Enumeration of risk severity levels for email threats."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ShieldMailAuthResult(BaseModel):
    """
    Explicit authentication result contract for ShieldMail authentication verification engine.

    Attributes:
        spf_result: SPF authentication result status ('pass', 'fail', 'softfail', 'none', etc.).
        dkim_result: DKIM authentication result status ('pass', 'fail', 'none', etc.).
        dmarc_result: DMARC authentication result status ('pass', 'fail', 'none', etc.).
        raw_header: Optional raw Authentication-Results header string.
    """
    model_config = ConfigDict(extra="ignore")

    spf_result: str | None = None
    dkim_result: str | None = None
    dmarc_result: str | None = None
    raw_header: str | None = None


# Alias for flexible integration
AuthenticationResult = ShieldMailAuthResult


class RiskFactor(BaseModel):
    """Individual heuristic or override risk factor contribution."""
    model_config = ConfigDict(extra="ignore")

    rule_id: str
    description: str
    points_added: float
    is_override: bool = False


class DetectionOutput(BaseModel):
    """
    Top-level output schema for AI detection engine inference.

    Attributes:
        is_threat: Flag indicating threat assessment (True if confidence >= 0.50 or risk_level in [HIGH, CRITICAL]).
        confidence_score: Normalized AI threat probability [0.0 - 1.0], 4 decimal places.
        risk_score: Combined heuristic + ML risk score [0.0 - 100.0], 2 decimal places.
        risk_level: Risk classification enum (LOW, MEDIUM, HIGH, CRITICAL).
        contributing_factors: List of human-readable descriptions for risk triggers.
        feature_vector_summary: Dictionary mapping feature names to extracted numeric values.
        inference_time_ms: Execution duration in milliseconds.
    """
    model_config = ConfigDict(extra="ignore")

    is_threat: bool = False
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_level: RiskLevel = RiskLevel.LOW
    contributing_factors: list[str] = Field(default_factory=list)
    feature_vector_summary: dict[str, float] = Field(default_factory=dict)
    inference_time_ms: float = 0.0
