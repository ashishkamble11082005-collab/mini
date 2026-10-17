"""
AI Detector Module for Email Analysis Pipeline.

Notice: The AI detection model is trained and evaluated on synthetic/simulated datasets.
Reported ROC-AUC and evaluation metrics reflect synthetic test performance only and
must not be cited as verified real-world baseline performance.
"""

from .config import (
    BASE_DIR,
    MODEL_DIR,
    MODEL_FILE,
    METADATA_FILE,
    WEIGHT_ML,
    PENALTY_EXPLICIT_AUTH_FAIL,
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
    ShieldMailAuthResult,
    AuthenticationResult,
)
from .feature_engineering import FeatureExtractor
from .risk_scorer import RiskEngine
from .predictor import EmailAIDetector, ModelArtifactError

__all__ = [
    "EmailAIDetector",
    "ModelArtifactError",
    "RiskEngine",
    "FeatureExtractor",
    "DetectionOutput",
    "ShieldMailAuthResult",
    "AuthenticationResult",
    "RiskLevel",
    "RiskFactor",
    "BASE_DIR",
    "MODEL_DIR",
    "MODEL_FILE",
    "METADATA_FILE",
    "WEIGHT_ML",
    "PENALTY_EXPLICIT_AUTH_FAIL",
    "PENALTY_AUTH_FAIL",
    "PENALTY_IP_URL",
    "PENALTY_ANCHOR_MISMATCH",
    "PENALTY_DEFANGED",
    "OVERRIDE_FLOOR_MIME_MISMATCH",
    "OVERRIDE_FLOOR_PHISH_TRIPWIRE",
    "URGENCY_KEYWORDS",
    "FEATURE_NAMES",
]
