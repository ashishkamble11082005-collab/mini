"""
AI Detector Configuration & Feature Manifest.

Defines model file paths, scoring weights, heuristic penalties, safety override floors,
urgency keyword lexicons, and the 22-feature manifest ordering with tri-state auth modeling.

Notice: The AI detection model is trained and evaluated on synthetic/simulated datasets.
Reported ROC-AUC and evaluation metrics reflect synthetic test performance only and
must not be cited as verified real-world baseline performance.
"""

from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------------
# 1. File Paths
# ---------------------------------------------------------------------------
BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent
MODEL_DIR: Final[Path] = BASE_DIR / "models"
MODEL_FILE: Final[Path] = MODEL_DIR / "random_forest_v2.joblib"
METADATA_FILE: Final[Path] = MODEL_DIR / "random_forest_v2_metadata.json"

# ---------------------------------------------------------------------------
# 2. Scoring & Heuristic Constants
# ---------------------------------------------------------------------------
WEIGHT_ML: Final[float] = 65.0
PENALTY_EXPLICIT_AUTH_FAIL: Final[float] = 15.0
PENALTY_AUTH_FAIL: Final[float] = PENALTY_EXPLICIT_AUTH_FAIL
PENALTY_IP_URL: Final[float] = 12.0
PENALTY_ANCHOR_MISMATCH: Final[float] = 18.0
PENALTY_DEFANGED: Final[float] = 10.0
OVERRIDE_FLOOR_MIME_MISMATCH: Final[float] = 85.0
OVERRIDE_FLOOR_PHISH_TRIPWIRE: Final[float] = 80.0

# ---------------------------------------------------------------------------
# 3. Lexicon Tokens
# ---------------------------------------------------------------------------
URGENCY_KEYWORDS: Final[list[str]] = [
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

# ---------------------------------------------------------------------------
# 4. Feature Manifest Order
# ---------------------------------------------------------------------------
FEATURE_NAMES: Final[list[str]] = [
    "spf_pass",
    "spf_fail",
    "spf_none",
    "dkim_pass",
    "dkim_fail",
    "dkim_none",
    "dmarc_pass",
    "dmarc_fail",
    "dmarc_none",
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
