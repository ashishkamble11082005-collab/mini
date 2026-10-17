"""
Offline Model Training, Evaluation, and Serialization Pipeline for Random Forest v2.

Generates 22-dimensional synthetic training dataset with tri-state auth modeling,
trains a Random Forest Classifier (v2), evaluates test performance & cross-validation,
and serializes model artifacts and metadata.

Notice: The AI detection model is trained and evaluated on synthetic/simulated datasets.
Reported ROC-AUC and evaluation metrics reflect synthetic test performance only and
must not be cited as verified real-world baseline performance.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Add mini directory to sys.path so it can be run from any working directory
mini_dir = Path(__file__).resolve().parent.parent
if str(mini_dir) not in sys.path:
    sys.path.insert(0, str(mini_dir))

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from ai_detector.config import (
    FEATURE_NAMES,
    METADATA_FILE,
    MODEL_DIR,
    MODEL_FILE,
    WEIGHT_ML,
    PENALTY_EXPLICIT_AUTH_FAIL,
    PENALTY_IP_URL,
    PENALTY_ANCHOR_MISMATCH,
    PENALTY_DEFANGED,
    OVERRIDE_FLOOR_MIME_MISMATCH,
    OVERRIDE_FLOOR_PHISH_TRIPWIRE,
)


def generate_v2_synthetic_dataset(n_samples: int = 4000) -> tuple[np.ndarray, np.ndarray]:
    """
    Generates realistic 22-dimensional synthetic feature vectors and labels for training.

    Profiles:
        1. Benign Corporate (40%): Auth PASS on all three, low urgency, legitimate URLs -> Label 0.
        2. Benign Unauthenticated / Legacy / Newsletters (25%): Auth NONE, clean text -> Label 0.
        3. Phishing / Spoofing (23%): Explicit FAIL on SPF/DMARC, high urgency, IP links -> Label 1.
        4. Payload Exploits (12%): mime_mismatch_detected = 1.0, anomalous hop delays -> Label 1.

    Args:
        n_samples: Total number of synthetic samples (default 4000).

    Returns:
        Tuple of (X: float32 array of shape (n_samples, 22), y: int32 array of shape (n_samples,)).
    """
    rng = np.random.default_rng(seed=42)

    n_corp = int(n_samples * 0.40)      # 1600
    n_unauth = int(n_samples * 0.25)    # 1000
    n_phish = int(n_samples * 0.23)     # 920
    n_exploit = n_samples - (n_corp + n_unauth + n_phish)  # 480

    rows: list[list[float]] = []
    labels: list[int] = []

    # 1. Benign Corporate (40%, Label 0)
    for _ in range(n_corp):
        row = [
            1.0, 0.0, 0.0,  # spf_pass, spf_fail, spf_none
            1.0, 0.0, 0.0,  # dkim_pass, dkim_fail, dkim_none
            1.0, 0.0, 0.0,  # dmarc_pass, dmarc_fail, dmarc_none
            float(rng.integers(1, 4)),       # hop_count
            float(rng.uniform(0.1, 3.0)),    # max_hop_delay_sec
            float(rng.uniform(200, 3000)),   # body_char_count
            float(rng.uniform(3.5, 4.5)),    # body_entropy
            float(rng.uniform(0.02, 0.12)),  # uppercase_ratio
            float(rng.poisson(lam=0.1)),     # urgency_word_count
            float(rng.uniform(1.0, 3.0)),    # html_to_text_ratio
            float(rng.integers(0, 4)),       # url_count
            0.0,                             # ip_literal_count
            0.0,                             # defanged_url_count
            0.0,                             # mismatched_anchor_count
            float(rng.integers(0, 2)),       # attachment_count
            0.0                              # mime_mismatch_detected
        ]
        rows.append(row)
        labels.append(0)

    # 2. Benign Unauthenticated / Legacy / Newsletters (25%, Label 0)
    for _ in range(n_unauth):
        row = [
            0.0, 0.0, 1.0,  # spf_pass, spf_fail, spf_none
            0.0, 0.0, 1.0,  # dkim_pass, dkim_fail, dkim_none
            0.0, 0.0, 1.0,  # dmarc_pass, dmarc_fail, dmarc_none
            float(rng.integers(1, 5)),       # hop_count
            float(rng.uniform(0.2, 5.0)),    # max_hop_delay_sec
            float(rng.uniform(300, 5000)),   # body_char_count
            float(rng.uniform(3.8, 4.6)),    # body_entropy
            float(rng.uniform(0.03, 0.15)),  # uppercase_ratio
            float(rng.poisson(lam=0.2)),     # urgency_word_count
            float(rng.uniform(1.5, 5.0)),    # html_to_text_ratio
            float(rng.integers(0, 6)),       # url_count
            0.0,                             # ip_literal_count
            0.0,                             # defanged_url_count
            0.0,                             # mismatched_anchor_count
            float(rng.integers(0, 2)),       # attachment_count
            0.0                              # mime_mismatch_detected
        ]
        rows.append(row)
        labels.append(0)

    # 3. Phishing / Spoofing (23%, Label 1)
    for _ in range(n_phish):
        dkim_f = float(rng.binomial(1, 0.8))
        row = [
            0.0, 1.0, 0.0,  # spf_pass, spf_fail, spf_none
            0.0, dkim_f, float(1.0 - dkim_f),  # dkim
            0.0, 1.0, 0.0,  # dmarc_pass, dmarc_fail, dmarc_none
            float(rng.integers(1, 5)),       # hop_count
            float(rng.uniform(0.2, 8.0)),    # max_hop_delay_sec
            float(rng.uniform(150, 1500)),   # body_char_count
            float(rng.uniform(4.2, 5.2)),    # body_entropy
            float(rng.uniform(0.15, 0.45)),  # uppercase_ratio
            float(rng.integers(2, 7)),       # urgency_word_count
            float(rng.uniform(1.0, 6.0)),    # html_to_text_ratio
            float(rng.integers(1, 6)),       # url_count
            float(rng.binomial(1, 0.4)),     # ip_literal_count
            float(rng.binomial(1, 0.4)),     # defanged_url_count
            float(rng.binomial(1, 0.7)),     # mismatched_anchor_count
            float(rng.integers(0, 2)),       # attachment_count
            0.0                              # mime_mismatch_detected
        ]
        rows.append(row)
        labels.append(1)

    # 4. Payload Exploits (12%, Label 1)
    for _ in range(n_exploit):
        spf_f = float(rng.binomial(1, 0.5))
        dkim_f = float(rng.binomial(1, 0.5))
        dmarc_f = float(rng.binomial(1, 0.5))
        row = [
            0.0, spf_f, float(1.0 - spf_f),    # spf
            0.0, dkim_f, float(1.0 - dkim_f),  # dkim
            0.0, dmarc_f, float(1.0 - dmarc_f),  # dmarc
            float(rng.integers(2, 8)),       # hop_count
            float(rng.uniform(5.0, 30.0)),   # max_hop_delay_sec
            float(rng.uniform(50, 2000)),    # body_char_count
            float(rng.uniform(4.5, 5.8)),    # body_entropy
            float(rng.uniform(0.10, 0.40)),  # uppercase_ratio
            float(rng.integers(1, 5)),       # urgency_word_count
            float(rng.uniform(0.5, 5.0)),    # html_to_text_ratio
            float(rng.integers(0, 5)),       # url_count
            float(rng.binomial(1, 0.3)),     # ip_literal_count
            float(rng.binomial(1, 0.3)),     # defanged_url_count
            float(rng.binomial(1, 0.4)),     # mismatched_anchor_count
            float(rng.integers(1, 4)),       # attachment_count
            float(rng.binomial(1, 0.9))      # mime_mismatch_detected
        ]
        rows.append(row)
        labels.append(1)

    X = np.array(rows, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)
    return X, y


def train_v2(output_dir: Optional[Path] = None) -> RandomForestClassifier:
    """
    Trains Random Forest Classifier v2 on synthetic dataset and serializes artifacts.

    Args:
        output_dir: Directory path to save model binary and metadata JSON.

    Returns:
        Trained RandomForestClassifier instance.
    """
    target_dir = output_dir or MODEL_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    model_path = target_dir / "random_forest_v2.joblib"
    metadata_path = target_dir / "random_forest_v2_metadata.json"

    print("Generating v2 synthetic training dataset (4000 samples)...")
    X, y = generate_v2_synthetic_dataset(n_samples=4000)

    # 80/20 train/test stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    hyperparameters = {
        "n_estimators": 300,
        "max_depth": 18,
        "min_samples_split": 4,
        "min_samples_leaf": 2,
        "class_weight": "balanced_subsample",
        "random_state": 42,
        "n_jobs": -1,
    }

    clf = RandomForestClassifier(**hyperparameters)

    # 5-fold Stratified K-Fold Cross Validation
    print("Running 5-fold Stratified K-Fold CV scoring ROC-AUC...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(clf, X_train, y_train, cv=skf, scoring="roc_auc", n_jobs=-1)
    print(f"5-Fold CV ROC-AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    print("Training Random Forest Classifier v2 on full training split...")
    clf.fit(X_train, y_train)

    # Evaluate test performance
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    auc = roc_auc_score(y_test, y_proba)
    report = classification_report(y_test, y_pred, target_names=["Benign", "Threat"])
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print("\n--- Model Evaluation Results (Random Forest v2) ---")
    print(f"ROC-AUC Score: {auc:.4f}")
    print(f"Confusion Matrix (2x2): TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print("\nClassification Report:")
    print(report)

    # Serialize model binary with compression
    print(f"Serializing trained model to {model_path}...")
    joblib.dump(clf, model_path, compress=3)

    # Feature manifest with explicit indices, types, and descriptions
    feature_descriptions = [
        ("spf_pass", "Binary indicator for SPF pass result (1.0 or 0.0)"),
        ("spf_fail", "Binary indicator for SPF fail/softfail/permerror result (1.0 or 0.0)"),
        ("spf_none", "Binary indicator for SPF neutral/none result (1.0 or 0.0)"),
        ("dkim_pass", "Binary indicator for DKIM pass result (1.0 or 0.0)"),
        ("dkim_fail", "Binary indicator for DKIM fail/invalid result (1.0 or 0.0)"),
        ("dkim_none", "Binary indicator for DKIM neutral/none result (1.0 or 0.0)"),
        ("dmarc_pass", "Binary indicator for DMARC pass result (1.0 or 0.0)"),
        ("dmarc_fail", "Binary indicator for DMARC fail result (1.0 or 0.0)"),
        ("dmarc_none", "Binary indicator for DMARC neutral/none result (1.0 or 0.0)"),
        ("hop_count", "Total count of parsed Received email routing hops"),
        ("max_hop_delay_sec", "Maximum delay in seconds detected across routing hops"),
        ("body_char_count", "Total character count of plain text email body"),
        ("body_entropy", "Shannon entropy score of plain text email body character distribution"),
        ("uppercase_ratio", "Ratio of uppercase characters to total body text length"),
        ("urgency_word_count", "Occurrences of social engineering and urgency lexicon keywords"),
        ("html_to_text_ratio", "Ratio of HTML character length to plain text character length"),
        ("url_count", "Total count of URLs extracted from email body text and HTML"),
        ("ip_literal_count", "Count of raw IP address literal URLs detected in payload"),
        ("defanged_url_count", "Count of defanged/obfuscated URLs (e.g. hxxp, [.] , (dot))"),
        ("mismatched_anchor_count", "Count of deceptive anchor text links mismatching netloc/domain"),
        ("attachment_count", "Total count of extracted email attachments"),
        ("mime_mismatch_detected", "Binary flag indicating magic bytes vs declared MIME content type mismatch (1.0 or 0.0)"),
    ]

    feature_manifest = [
        {
            "index": idx,
            "name": name,
            "type": "float32",
            "description": desc,
        }
        for idx, (name, desc) in enumerate(feature_descriptions)
    ]

    threshold_constants = {
        "WEIGHT_ML": WEIGHT_ML,
        "PENALTY_EXPLICIT_AUTH_FAIL": PENALTY_EXPLICIT_AUTH_FAIL,
        "PENALTY_IP_URL": PENALTY_IP_URL,
        "PENALTY_ANCHOR_MISMATCH": PENALTY_ANCHOR_MISMATCH,
        "PENALTY_DEFANGED": PENALTY_DEFANGED,
        "OVERRIDE_FLOOR_MIME_MISMATCH": OVERRIDE_FLOOR_MIME_MISMATCH,
        "OVERRIDE_FLOOR_PHISH_TRIPWIRE": OVERRIDE_FLOOR_PHISH_TRIPWIRE,
        "ML_THREAT_CONFIDENCE_THRESHOLD": 0.50,
        "RISK_TIER_CRITICAL_MIN": 80.0,
        "RISK_TIER_HIGH_MIN": 60.0,
        "RISK_TIER_MEDIUM_MIN": 35.0,
        "RISK_TIER_LOW_MIN": 0.0,
    }

    # Export feature metadata JSON
    metadata = {
        "model_version": "v2.0.0",
        "model_type": "RandomForestClassifier",
        "dataset_notice": "TRAINED AND EVALUATED EXCLUSIVELY ON SYNTHETIC/SIMULATED DATASETS. REPORTED METRICS REFLECT SYNTHETIC TEST PERFORMANCE ONLY AND MUST NOT BE CITED AS VERIFIED REAL-WORLD BASELINE PERFORMANCE.",
        "num_features": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "feature_manifest": feature_manifest,
        "threshold_constants": threshold_constants,
        "categorical_encodings": {
            "auth_states": ["PASS", "FAIL", "NONE"]
        },
        "hyperparameters": hyperparameters,
        "trained_at_iso": datetime.now(timezone.utc).isoformat(),
        "roc_auc_score": float(auc),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
    }

    print(f"Exporting feature metadata to {metadata_path}...")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("Random Forest v2 training & serialization complete!")
    return clf


def train_and_serialize(output_dir: Optional[Path] = None) -> RandomForestClassifier:
    """Alias for train_v2 to maintain backwards compatibility with imports."""
    return train_v2(output_dir)


if __name__ == "__main__":
    train_v2()
