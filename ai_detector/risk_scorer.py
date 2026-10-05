"""
Deterministic Heuristic Evaluator & Hybrid Risk Scorer for AI Detection Subsystem.

Combines ML classifier confidence scores with heuristic penalty rules and safety floor overrides.
"""

from typing import Optional

from ai_detector.config import (
    WEIGHT_ML,
    PENALTY_AUTH_FAIL,
    PENALTY_IP_URL,
    PENALTY_ANCHOR_MISMATCH,
    PENALTY_DEFANGED,
    OVERRIDE_FLOOR_MIME_MISMATCH,
    OVERRIDE_FLOOR_PHISH_TRIPWIRE,
)
from ai_detector.schemas import RiskLevel


class RiskEngine:
    """Combines machine learning posterior probabilities with heuristic rule penalties and safety floors."""

    def evaluate(
        self, confidence: float, features: Optional[dict[str, float]] = None
    ) -> tuple[float, RiskLevel, list[str]]:
        """
        Evaluates machine learning confidence score and feature vector dictionary to determine final risk score.

        Args:
            confidence: ML model predicted threat probability in range [0.0, 1.0].
            features: Dictionary mapping feature names to numerical values.

        Returns:
            Tuple of (final_score: float [0.0 - 100.0], risk_level: RiskLevel, contributing_factors: list[str]).
        """
        if features is None:
            features = {}

        # Clamp confidence to valid probability bounds [0.0, 1.0]
        safe_confidence = max(0.0, min(1.0, float(confidence)))

        additive_penalties = 0.0
        factors: list[str] = []

        # 1. Authentication Failure Penalty
        spf_pass = float(features.get("spf_pass", 0.0))
        dmarc_pass = float(features.get("dmarc_pass", 0.0))
        if spf_pass == 0.0 and dmarc_pass == 0.0:
            additive_penalties += PENALTY_AUTH_FAIL
            factors.append("Failed SPF and DMARC alignment")

        # 2. Raw IP-Literal URL Penalty
        ip_count = float(features.get("ip_literal_count", 0.0))
        if ip_count > 0:
            additive_penalties += PENALTY_IP_URL
            factors.append(f"Contains {int(ip_count)} raw IP-literal link(s)")

        # 3. Mismatched Anchor Text Penalty
        mismatched_anchors = float(features.get("mismatched_anchor_count", 0.0))
        if mismatched_anchors > 0:
            additive_penalties += PENALTY_ANCHOR_MISMATCH
            factors.append("Detected deceptive anchor text host mismatch")

        # 4. Defanged URL Evasion Penalty
        defanged_count = float(features.get("defanged_url_count", 0.0))
        if defanged_count > 0:
            additive_penalties += PENALTY_DEFANGED
            factors.append("Found defanged/obfuscated URL structures")

        # Calculate base ML + Heuristic penalty score
        base_score = min(100.0, (WEIGHT_ML * safe_confidence) + additive_penalties)

        # 5. Safety Override Floors
        floor = 0.0

        mime_mismatch = float(features.get("mime_mismatch_detected", 0.0))
        if mime_mismatch == 1.0:
            floor = max(floor, OVERRIDE_FLOOR_MIME_MISMATCH)
            factors.append("CRITICAL: Attachment magic bytes mismatch detected (disguised payload)")

        if mismatched_anchors > 0 and (spf_pass == 0.0 or dmarc_pass == 0.0):
            floor = max(floor, OVERRIDE_FLOOR_PHISH_TRIPWIRE)
            factors.append("CRITICAL: Deceptive hyperlink combined with unauthenticated domain origin")

        # Compute final clamped & rounded score
        final_score = round(max(base_score, floor), 2)
        final_score = max(0.0, min(100.0, final_score))

        # 6. Risk Tier Mapping
        if final_score >= 80.0:
            level = RiskLevel.CRITICAL
        elif final_score >= 60.0:
            level = RiskLevel.HIGH
        elif final_score >= 35.0:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return final_score, level, factors
