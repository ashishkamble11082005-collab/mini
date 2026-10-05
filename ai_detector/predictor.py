"""
Runtime Inference Orchestrator for AI Detection Subsystem.

Loads serialized model artifact and feature metadata to execute high-performance threat predictions on ParsedEmailResult.
"""

import json
import threading
import time
from pathlib import Path
from typing import Optional

import joblib
import numpy as np

from ai_detector.config import FEATURE_NAMES, METADATA_FILE, MODEL_DIR, MODEL_FILE
from ai_detector.feature_engineering import FeatureExtractor
from ai_detector.risk_scorer import RiskEngine
from ai_detector.schemas import DetectionOutput, RiskLevel
from email_parser.schemas import ParsedEmailResult


class EmailAIDetector:
    """Thread-safe runtime AI threat predictor for email payloads."""

    _lock = threading.Lock()

    def __init__(
        self,
        model_path: Optional[Path] = None,
        metadata_path: Optional[Path] = None,
    ) -> None:
        """
        Initializes predictor by loading model binary and metadata JSON into memory.

        Args:
            model_path: Optional path to serialized model binary (.joblib).
            metadata_path: Optional path to feature metadata JSON.
        """
        self.model_path = model_path or MODEL_FILE
        self.metadata_path = metadata_path or METADATA_FILE
        self.extractor = FeatureExtractor()
        self.risk_engine = RiskEngine()

        with self._lock:
            # Auto-train model artifact if missing
            if not self.model_path.exists() or not self.metadata_path.exists():
                from ai_detector.train import train_and_serialize
                train_and_serialize(self.model_path.parent)

            # Load model artifact into memory
            self.model = joblib.load(self.model_path)

            # Load and validate metadata
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

            meta_features = self.metadata.get("feature_names", [])
            if meta_features and meta_features != FEATURE_NAMES:
                raise ValueError(
                    f"Model feature mismatch. Expected {len(FEATURE_NAMES)} features, got {len(meta_features)}"
                )

    def predict(self, parsed: Optional[ParsedEmailResult]) -> DetectionOutput:
        """
        Executes end-to-end threat detection on ParsedEmailResult.

        Args:
            parsed: ParsedEmailResult instance or None.

        Returns:
            Validated DetectionOutput schema.
        """
        start_time = time.perf_counter()

        # 1. Feature Vector Extraction
        features_arr, features_dict = self.extractor.extract_vector(parsed)

        # 2. Model Probability Inference
        # Reshape to (1, 16) for scikit-learn estimator interface
        input_matrix = np.array([features_arr], dtype=np.float32)
        probs = self.model.predict_proba(input_matrix)[0]

        # Extract posterior probability for positive class (Threat = label 1)
        confidence = float(probs[1]) if len(probs) > 1 else float(probs[0])
        confidence_score = round(max(0.0, min(1.0, confidence)), 4)

        # 3. Hybrid Risk Scoring & Safety Floors
        risk_score, level, factors = self.risk_engine.evaluate(
            confidence=confidence_score, features=features_dict
        )

        # 4. Threat Decision Rule
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
