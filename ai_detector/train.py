"""
Offline Model Training, Evaluation, and Serialization Pipeline.

Generates synthetic training dataset, trains a Random Forest Classifier,
evaluates test performance, and serializes the model artifact and metadata JSON.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

from ai_detector.config import FEATURE_NAMES, METADATA_FILE, MODEL_DIR, MODEL_FILE


def generate_synthetic_training_data(n_samples: int = 3000) -> tuple[np.ndarray, np.ndarray]:
    """
    Generates realistic synthetic feature vectors and labels for training.

    Profiles:
        - Profile A (Benign clean): 1500 samples (Label 0)
        - Profile B (Marketing/Transactional): 500 samples (Label 0)
        - Profile C (Credential Phishing): 700 samples (Label 1)
        - Profile D (Malware/Exploit): 300 samples (Label 1)

    Args:
        n_samples: Total number of synthetic samples (default 3000).

    Returns:
        Tuple of (X: float32 array of shape (n_samples, 16), y: int32 array of shape (n_samples,)).
    """
    rng = np.random.default_rng(seed=42)

    nA = int(n_samples * 0.50)  # 1500
    nB = int(n_samples * 0.1667)  # 500
    nC = int(n_samples * 0.2333)  # 700
    nD = n_samples - (nA + nB + nC)  # 300

    rows: list[list[float]] = []
    labels: list[int] = []

    # -----------------------------------------------------------------------
    # Profile A: Benign Clean (1500 samples, Label 0)
    # -----------------------------------------------------------------------
    for _ in range(nA):
        row = [
            1.0,  # spf_pass
            1.0,  # dkim_pass
            1.0,  # dmarc_pass
            float(rng.integers(1, 4)),  # hop_count
            float(rng.uniform(0.1, 3.0)),  # max_hop_delay_sec
            float(rng.uniform(200, 3000)),  # body_char_count
            float(rng.uniform(3.5, 4.5)),  # body_entropy
            float(rng.uniform(0.02, 0.12)),  # uppercase_ratio
            float(rng.poisson(lam=0.1)),  # urgency_word_count
            float(rng.uniform(1.0, 3.0)),  # html_to_text_ratio
            float(rng.integers(0, 4)),  # url_count
            0.0,  # ip_literal_count
            0.0,  # defanged_url_count
            0.0,  # mismatched_anchor_count
            float(rng.integers(0, 2)),  # attachment_count
            0.0,  # mime_mismatch_detected
        ]
        rows.append(row)
        labels.append(0)

    # -----------------------------------------------------------------------
    # Profile B: Marketing / Transactional (500 samples, Label 0)
    # -----------------------------------------------------------------------
    for _ in range(nB):
        row = [
            float(rng.binomial(1, 0.8)),  # spf_pass
            float(rng.binomial(1, 0.9)),  # dkim_pass
            float(rng.binomial(1, 0.7)),  # dmarc_pass
            float(rng.integers(2, 6)),  # hop_count
            float(rng.uniform(0.5, 10.0)),  # max_hop_delay_sec
            float(rng.uniform(1000, 8000)),  # body_char_count
            float(rng.uniform(4.0, 4.8)),  # body_entropy
            float(rng.uniform(0.05, 0.20)),  # uppercase_ratio
            float(rng.integers(0, 2)),  # urgency_word_count
            float(rng.uniform(3.0, 10.0)),  # html_to_text_ratio
            float(rng.integers(3, 15)),  # url_count
            0.0,  # ip_literal_count
            0.0,  # defanged_url_count
            0.0,  # mismatched_anchor_count
            float(rng.integers(0, 1)),  # attachment_count
            0.0,  # mime_mismatch_detected
        ]
        rows.append(row)
        labels.append(0)

    # -----------------------------------------------------------------------
    # Profile C: Credential Phishing (700 samples, Label 1)
    # -----------------------------------------------------------------------
    for _ in range(nC):
        row = [
            float(rng.binomial(1, 0.2)),  # spf_pass
            float(rng.binomial(1, 0.2)),  # dkim_pass
            float(rng.binomial(1, 0.1)),  # dmarc_pass
            float(rng.integers(1, 5)),  # hop_count
            float(rng.uniform(0.2, 8.0)),  # max_hop_delay_sec
            float(rng.uniform(150, 1500)),  # body_char_count
            float(rng.uniform(4.2, 5.2)),  # body_entropy
            float(rng.uniform(0.15, 0.45)),  # uppercase_ratio
            float(rng.integers(2, 7)),  # urgency_word_count
            float(rng.uniform(1.0, 6.0)),  # html_to_text_ratio
            float(rng.integers(1, 6)),  # url_count
            float(rng.binomial(1, 0.3)),  # ip_literal_count
            float(rng.binomial(1, 0.4)),  # defanged_url_count
            float(rng.binomial(1, 0.6)),  # mismatched_anchor_count
            float(rng.integers(0, 2)),  # attachment_count
            0.0,  # mime_mismatch_detected
        ]
        rows.append(row)
        labels.append(1)

    # -----------------------------------------------------------------------
    # Profile D: Malware / Exploit (300 samples, Label 1)
    # -----------------------------------------------------------------------
    for _ in range(nD):
        row = [
            float(rng.binomial(1, 0.1)),  # spf_pass
            float(rng.binomial(1, 0.1)),  # dkim_pass
            float(rng.binomial(1, 0.1)),  # dmarc_pass
            float(rng.integers(1, 8)),  # hop_count
            float(rng.uniform(0.5, 30.0)),  # max_hop_delay_sec
            float(rng.uniform(50, 2000)),  # body_char_count
            float(rng.uniform(4.5, 5.8)),  # body_entropy
            float(rng.uniform(0.10, 0.40)),  # uppercase_ratio
            float(rng.integers(1, 5)),  # urgency_word_count
            float(rng.uniform(0.5, 5.0)),  # html_to_text_ratio
            float(rng.integers(0, 5)),  # url_count
            float(rng.binomial(1, 0.2)),  # ip_literal_count
            float(rng.binomial(1, 0.3)),  # defanged_url_count
            float(rng.binomial(1, 0.3)),  # mismatched_anchor_count
            float(rng.integers(1, 4)),  # attachment_count
            float(rng.binomial(1, 0.85)),  # mime_mismatch_detected
        ]
        rows.append(row)
        labels.append(1)

    X = np.array(rows, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)
    return X, y


def train_and_serialize(output_dir: Path = MODEL_DIR) -> RandomForestClassifier:
    """
    Trains the Random Forest model on synthetic data and serializes artifacts.

    Args:
        output_dir: Directory path to save model binary and metadata JSON.

    Returns:
        Trained RandomForestClassifier instance.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "random_forest_v1.joblib"
    metadata_path = output_dir / "feature_metadata.json"

    print("Generating synthetic training dataset (3000 samples)...")
    X, y = generate_synthetic_training_data(n_samples=3000)

    # 80/20 train/test stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    hyperparameters = {
        "n_estimators": 250,
        "max_depth": 16,
        "min_samples_split": 4,
        "min_samples_leaf": 2,
        "class_weight": "balanced_subsample",
        "random_state": 42,
        "n_jobs": -1,
    }

    print("Training Random Forest Classifier...")
    clf = RandomForestClassifier(**hyperparameters)
    clf.fit(X_train, y_train)

    # Evaluate test performance
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    auc = roc_auc_score(y_test, y_proba)
    report = classification_report(y_test, y_pred, target_names=["Benign", "Threat"])

    print("\n--- Model Evaluation Results ---")
    print(f"ROC-AUC Score: {auc:.4f}")
    print("\nClassification Report:")
    print(report)

    # Serialize model binary with compression
    print(f"Serializing trained model to {model_path}...")
    joblib.dump(clf, model_path, compress=3)

    # Export feature metadata JSON
    metadata = {
        "feature_names": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "model_type": "RandomForestClassifier",
        "hyperparameters": hyperparameters,
        "trained_at_iso": datetime.now(timezone.utc).isoformat(),
        "roc_auc_score": float(auc),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
    }

    print(f"Exporting feature metadata to {metadata_path}...")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("Model training & serialization complete!")
    return clf


if __name__ == "__main__":
    train_and_serialize(MODEL_DIR)
