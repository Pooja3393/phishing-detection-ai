"""Validate and train a URL classifier from the app's 30-feature CSV format."""

from datetime import datetime, timezone
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from feature_schema import FEATURE_NAMES, TARGET_CANDIDATES, canonical_column

TRAIN_FEATURES = [name for name in FEATURE_NAMES if name != "HTTPS"]
PHISHING_THRESHOLD = 0.65
LEGITIMATE_THRESHOLD = 0.35
USER_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model_user.pkl")


def inspect_dataset(frame):
    if frame.empty:
        raise ValueError("The uploaded CSV has no rows.")
    canonical = {}
    for column in frame.columns:
        key = canonical_column(column)
        if key in canonical:
            raise ValueError(f"The CSV has duplicate headers after case/space normalization: {column}")
        canonical[key] = column
    target = next((canonical[key] for key in TARGET_CANDIDATES if key in canonical), None)
    if target is None:
        raise ValueError("Could not find a target column. Name it class, label, target, is_phishing, or phishing.")
    feature_by_key = {canonical_column(name): name for name in FEATURE_NAMES}
    missing = [name for name in FEATURE_NAMES if canonical_column(name) not in canonical]
    if missing:
        raise ValueError("This trainer needs the project's 30 named URL features. Missing: " + ", ".join(missing))
    return target, {name: canonical[canonical_column(name)] for name in FEATURE_NAMES}


def train_uploaded_dataset(frame, target_column, phishing_value):
    target, feature_columns = inspect_dataset(frame)
    if target_column != target:
        raise ValueError("Select the detected label column shown by the app.")
    if frame[target].isna().any():
        raise ValueError("The target label column contains empty values.")
    labels = frame[target].astype(str).str.strip()
    phish_label = str(phishing_value).strip()
    classes = set(labels.unique())
    if len(classes) != 2 or phish_label not in classes:
        raise ValueError("Choose which of the two label values means phishing.")
    legitimate_label = next(value for value in classes if value != phish_label)

    X = frame[[feature_columns[name] for name in TRAIN_FEATURES]].copy()
    X.columns = TRAIN_FEATURES
    X = X.apply(pd.to_numeric, errors="coerce")
    if X.isna().any().any() or not np.isfinite(X.to_numpy(dtype=float)).all():
        raise ValueError("Feature columns must contain numeric, non-empty values only.")
    invalid = sorted(set(np.unique(X.to_numpy())) - {-1, 0, 1})
    if invalid:
        raise ValueError("The legacy URL feature format accepts only -1, 0, or 1. Unsupported values: " + str(invalid[:8]))

    y = (labels == phish_label).astype(int)
    counts = y.value_counts()
    if len(counts) != 2 or int(counts.min()) < 10:
        raise ValueError("At least 10 phishing and 10 legitimate rows are required for a useful holdout evaluation.")

    # Keep a stratified test set untouched. Choose between two tree ensembles
    # on validation data, then refit the winner before final test reporting.
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.25, random_state=43, stratify=y_train_val
    )
    candidates = [
        RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample", n_jobs=-1, random_state=42),
        ExtraTreesClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced", n_jobs=-1, random_state=42),
    ]
    chosen = max(
        candidates,
        key=lambda candidate: _validation_score(candidate, X_train, y_train, X_val, y_val),
    )
    chosen.fit(X_train, y_train)
    positive_threshold, negative_threshold, validation_fpr = _select_thresholds(chosen, X_val, y_val)
    chosen.fit(X_train_val, y_train_val)
    probabilities = chosen.predict_proba(X_test)[:, list(chosen.classes_).index(1)]
    predictions = np.where(probabilities >= positive_threshold, 1, np.where(probabilities <= negative_threshold, 0, -1))
    # Exclude inconclusive results from binary class metrics; report coverage separately.
    classified = predictions >= 0
    matrix = confusion_matrix(y_test[classified], predictions[classified], labels=[1, 0]).tolist() if classified.any() else [[0, 0], [0, 0]]
    metrics = {
        "test_rows": int(len(y_test)),
        "coverage_percent": round(float(classified.mean() * 100), 2),
        "accuracy_percent": round(float(accuracy_score(y_test[classified], predictions[classified]) * 100), 2) if classified.any() else 0.0,
        "balanced_accuracy_percent": round(float(balanced_accuracy_score(y_test[classified], predictions[classified]) * 100), 2) if classified.any() and len(set(y_test[classified])) > 1 else 0.0,
        "phishing_precision_percent": round(float(precision_score(y_test[classified], predictions[classified], pos_label=1, zero_division=0) * 100), 2),
        "phishing_recall_percent": round(float(recall_score(y_test[classified], predictions[classified], pos_label=1, zero_division=0) * 100), 2),
        "phishing_f1_percent": round(float(f1_score(y_test[classified], predictions[classified], pos_label=1, zero_division=0) * 100), 2),
        "confusion_matrix_phishing_then_legitimate": matrix,
        "matrix_labels": ["phishing", "legitimate"],
        "validation_false_positive_rate_percent": round(validation_fpr * 100, 2),
    }
    bundle = {
        "model": chosen,
        "feature_names": TRAIN_FEATURES,
        "threshold": positive_threshold,
        "legitimate_threshold": negative_threshold,
        "decision_policy": "Validation threshold selected for at most 5% false-positive rate",
        "model_name": type(chosen).__name__,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_rows": int(len(frame)),
        "label_column": target,
        "phishing_label": phish_label,
        "legitimate_label": legitimate_label,
        "excluded_feature": "HTTPS",
        "metrics": metrics,
    }
    model_path = os.path.abspath(USER_MODEL_PATH)
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(bundle, model_path)
    return bundle, model_path


def _validation_score(model, X_train, y_train, X_val, y_val):
    model.fit(X_train, y_train)
    probabilities = model.predict_proba(X_val)[:, list(model.classes_).index(1)]
    positive_threshold, negative_threshold, _ = _select_thresholds(model, X_val, y_val)
    predictions = np.where(probabilities >= positive_threshold, 1, np.where(probabilities <= negative_threshold, 0, -1))
    classified = predictions >= 0
    if not classified.any() or len(set(y_val[classified])) < 2:
        return 0
    coverage = float(classified.mean())
    return balanced_accuracy_score(y_val[classified], predictions[classified]) * coverage


def _select_thresholds(model, X_val, y_val):
    probabilities = model.predict_proba(X_val)[:, list(model.classes_).index(1)]
    actual_phishing = y_val.to_numpy() == 1
    actual_legitimate = ~actual_phishing
    candidates = sorted(set(float(value) for value in probabilities) | {PHISHING_THRESHOLD, 1.0})
    feasible = []
    for threshold in candidates:
        predicted_phishing = probabilities >= threshold
        false_positive_rate = float(predicted_phishing[actual_legitimate].mean()) if actual_legitimate.any() else 1.0
        recall = float(predicted_phishing[actual_phishing].mean()) if actual_phishing.any() else 0.0
        if false_positive_rate <= 0.05:
            feasible.append((recall, -false_positive_rate, threshold, false_positive_rate))
    if not feasible:
        threshold, fpr = 1.0, 0.0
    else:
        _, _, threshold, fpr = max(feasible)
    return threshold, 1.0 - threshold, fpr
