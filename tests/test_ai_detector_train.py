"""
Unit tests for mini.ai_detector.train module.
"""

import json
from pathlib import Path
import numpy as np
from ai_detector.train import generate_synthetic_training_data, train_and_serialize
from ai_detector.config import FEATURE_NAMES


def test_generate_synthetic_training_data():
    X, y = generate_synthetic_training_data(n_samples=3000)

    assert isinstance(X, np.ndarray)
    assert isinstance(y, np.ndarray)
    assert X.shape == (3000, 16)
    assert y.shape == (3000,)
    assert X.dtype == np.float32
    assert y.dtype == np.int32

    # Verify binary labels (0 for benign, 1 for threat)
    unique_labels = set(np.unique(y))
    assert unique_labels == {0, 1}


def test_train_and_serialize(tmp_path: Path):
    clf = train_and_serialize(output_dir=tmp_path)

    model_file = tmp_path / "random_forest_v1.joblib"
    metadata_file = tmp_path / "feature_metadata.json"

    assert model_file.exists()
    assert metadata_file.exists()

    with open(metadata_file, "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["n_features"] == 16
    assert meta["feature_names"] == FEATURE_NAMES
    assert meta["model_type"] == "RandomForestClassifier"
    assert "roc_auc_score" in meta
    assert meta["train_samples"] + meta["test_samples"] == 3000
