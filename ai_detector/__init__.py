"""
AI Detector Module for Email Analysis Pipeline.
"""

from .config import (
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
from .schemas import (
    RiskLevel,
    RiskFactor,
    DetectionOutput,
)
from .feature_engineering import FeatureExtractor
from .risk_scorer import RiskEngine
from .predictor import EmailAIDetector

__all__ = [
    "EmailAIDetector",
    "RiskEngine",
    "FeatureExtractor",
    "DetectionOutput",
    "RiskLevel",
    "RiskFactor",
    "BASE_DIR",
    "MODEL_DIR",
    "MODEL_FILE",
    "METADATA_FILE",
    "WEIGHT_ML",
    "PENALTY_AUTH_FAIL",
    "PENALTY_IP_URL",
    "PENALTY_ANCHOR_MISMATCH",
    "PENALTY_DEFANGED",
    "OVERRIDE_FLOOR_MIME_MISMATCH",
    "OVERRIDE_FLOOR_PHISH_TRIPWIRE",
    "URGENCY_KEYWORDS",
    "FEATURE_NAMES",
]
