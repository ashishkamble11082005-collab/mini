"""
Runtime Inference Orchestrator for AI Detection Subsystem.

Loads serialized model artifact (v2) and feature metadata to execute high-performance threat predictions on ParsedEmailResult.

Notice: The AI detection model is trained and evaluated on synthetic/simulated datasets.
Reported ROC-AUC and evaluation metrics reflect synthetic test performance only and
must not be cited as verified real-world baseline performance.
"""

import json
import threading
import time
from pathlib import Path
from typing import Any

# pyrefly: ignore [missing-import]
import joblib

from ai_detector.config import FEATURE_NAMES, METADATA_FILE, MODEL_FILE
from ai_detector.feature_engineering import FeatureExtractor
from ai_detector.risk_scorer import RiskEngine
from ai_detector.schemas import DetectionOutput, RiskLevel, ShieldMailAuthResult
from email_parser.schemas import ParsedEmailResult, AuthResults


def _status_value(value: Any) -> str | None:
    """Extract a normalized status from ShieldMail auth result values."""
    if isinstance(value, dict):
        value = value.get("status", value.get("result"))
    elif value is not None and hasattr(value, "status"):
        value = getattr(value, "status")
    if value is not None and hasattr(value, "value"):
        value = value.value
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_authentication(authentication: Any) -> ShieldMailAuthResult | AuthResults | None:
    """
    Normalize ShieldMail's nested authentication analyzer output or a flat auth result.

    Accepted nested shape: {"spf": {"status": "PASS"}, "dkim": ..., "dmarc": ...}.
    Explicitly supplied authentication always takes precedence over unverified message headers.
    """
    if authentication is None:
        return None
    if isinstance(authentication, ShieldMailAuthResult):
        return authentication
    if isinstance(authentication, dict):
        def pick(name: str) -> str | None:
            nested = authentication.get(name)
            if nested is not None:
                return _status_value(nested)
            for key in (f"{name}_result", f"{name}_status"):
                if key in authentication:
                    return _status_value(authentication.get(key))
            return None

        raw_header = authentication.get("raw_header")
        return ShieldMailAuthResult(
            spf_result=pick("spf"),
            dkim_result=pick("dkim"),
            dmarc_result=pick("dmarc"),
            raw_header=raw_header if isinstance(raw_header, str) else None,
        )

    # Existing parser AuthResults or compatible result objects.
    return ShieldMailAuthResult(
        spf_result=_status_value(getattr(authentication, "spf_result", None)),
        dkim_result=_status_value(getattr(authentication, "dkim_result", None)),
        dmarc_result=_status_value(getattr(authentication, "dmarc_result", None)),
        raw_header=getattr(authentication, "raw_header", None),
    )


class ModelArtifactError(Exception):
    """Raised when model artifacts (binary or metadata) are missing, unreadable, or invalid."""

    pass


class EmailAIDetector:
    """Thread-safe runtime AI threat predictor for email payloads."""

    _lock = threading.Lock()

    def __init__(
        self,
        model_path: Path | None = None,
        metadata_path: Path | None = None,
    ) -> None:
        """
        Initializes predictor by loading pre-trained production model binary (v2) and metadata JSON.

        Args:
            model_path: Optional path to serialized model binary (.joblib).
            metadata_path: Optional path to feature metadata JSON.

        Raises:
            FileNotFoundError: If model binary or metadata JSON file does not exist on disk.
            ModelArtifactError: If artifacts are unreadable, corrupted, or have feature schema mismatches.
        """
        self.model_path = model_path or MODEL_FILE
        self.metadata_path = metadata_path or METADATA_FILE
        self.extractor = FeatureExtractor()
        self.risk_engine = RiskEngine()

        with self._lock:
            # 1. Fail-fast validation: Verify existence of production artifacts
            if not self.model_path.exists():
                raise FileNotFoundError(
                    f"Pre-trained production model artifact not found at: '{self.model_path}'"
                )
            if not self.metadata_path.exists():
                raise FileNotFoundError(
                    f"Feature metadata production artifact not found at: '{self.metadata_path}'"
                )

            # 2. Fail-fast validation: Load pre-trained model binary
            try:
                self.model = joblib.load(self.model_path)
            except Exception as e:
                raise ModelArtifactError(
                    f"Failed to load pre-trained model artifact binary from '{self.model_path}': {e}"
                ) from e

            if not hasattr(self.model, "predict_proba"):
                raise ModelArtifactError(
                    f"Model artifact loaded from '{self.model_path}' is invalid: missing 'predict_proba' method."
                )
            model_features = getattr(self.model, "n_features_in_", None)
            if model_features != len(FEATURE_NAMES):
                raise ModelArtifactError(
                    f"Model artifact feature count mismatch: expected {len(FEATURE_NAMES)}, got {model_features}."
                )
            model_classes = list(getattr(self.model, "classes_", []))
            if 1 not in model_classes:
                raise ModelArtifactError(
                    f"Model artifact must contain threat class label 1; found classes {model_classes}."
                )

            # 3. Fail-fast validation: Parse metadata JSON
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata: dict[str, Any] = json.load(f)
            except Exception as e:
                raise ModelArtifactError(
                    f"Failed to read/parse feature metadata artifact JSON from '{self.metadata_path}': {e}"
                ) from e

            if not isinstance(self.metadata, dict):
                raise ModelArtifactError(
                    f"Feature metadata artifact at '{self.metadata_path}' must be a JSON dictionary."
                )

            # 4. Fail-fast validation: Check feature schema alignment
            meta_features = self.metadata.get("feature_names", [])
            num_feats = self.metadata.get(
                "num_features", self.metadata.get("n_features", len(meta_features))
            )

            expected_len = len(FEATURE_NAMES)
            if num_feats != expected_len or meta_features != FEATURE_NAMES:
                raise ModelArtifactError(
                    f"Model feature schema mismatch in '{self.metadata_path}'. "
                    f"Expected {expected_len} features in the exact manifest order, got {num_feats}."
                )

    def predict(
        self,
        parsed: ParsedEmailResult | None = None,
        authentication: ShieldMailAuthResult | AuthResults | dict | None = None,
    ) -> DetectionOutput:
        """
        Executes end-to-end threat detection on ParsedEmailResult with explicit ShieldMail authentication payload.

        Args:
            parsed: ParsedEmailResult instance or None.
            authentication: Explicit ShieldMail authentication result object (ShieldMailAuthResult, AuthResults, or dict) or None.

        Returns:
            Validated DetectionOutput schema.
        """
        start_time = time.perf_counter()

        # Explicit verified ShieldMail results take precedence over unverified email headers.
        auth_payload = _normalize_authentication(authentication)
        if auth_payload is None and parsed and getattr(parsed, "headers", None):
            auth_payload = _normalize_authentication(
                getattr(parsed.headers, "auth_results", None)
            )

        # 1. Feature Vector Extraction
        features_arr, features_dict = self.extractor.extract_vector(
            parsed, auth_result=auth_payload
        )

        # 2. Validate feature vector dimension
        if features_arr.shape != (22,):
            raise ValueError(
                f"Feature vector shape mismatch. Expected (22,), got {features_arr.shape}"
            )

        # 3. Model Probability Inference (Pure ML Model Confidence [0.0, 1.0])
        probs = self.model.predict_proba([features_arr])[0]

        # Select the probability by class label, not by assuming class 1 is at index 1.
        classes = list(getattr(self.model, "classes_", []))
        try:
            threat_index = classes.index(1)
        except ValueError as exc:
            raise ModelArtifactError(
                f"Loaded model does not expose threat class label 1: {classes}"
            ) from exc
        if threat_index >= len(probs):
            raise ModelArtifactError("Model probability output does not match its class labels.")
        confidence = float(probs[threat_index])
        # Raw ML model confidence score clamped to [0.0, 1.0], rounded to 4 decimal places
        confidence_score = round(max(0.0, min(1.0, confidence)), 4)

        # 4. Hybrid Risk Scoring & Safety Floors
        # Note: ML model confidence_score is kept completely separate and is NEVER mutated by heuristic overrides.
        risk_score, level, factors = self.risk_engine.evaluate(
            confidence=confidence_score, features=features_dict
        )

        # 5. Threat Decision Rule
        is_threat = bool(
            confidence_score >= 0.50 or level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        )

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return DetectionOutput(
            is_threat=is_threat,
            confidence_score=confidence_score,
            risk_score=risk_score,
            risk_level=level,
            contributing_factors=factors,
            feature_vector_summary=features_dict,
            inference_time_ms=duration_ms,
        )
