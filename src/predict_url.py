"""Load a phishing classifier and make a cautious 30-feature prediction."""

import os

import joblib
import pandas as pd

from feature_extractor import extract_features
from feature_schema import FEATURE_NAMES

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(CURRENT_DIR, "..", "models")
USER_MODEL_PATH = os.path.join(MODELS_DIR, "phishing_model_user.pkl")
BASE_MODEL_PATH = os.path.join(MODELS_DIR, "phishing_model.pkl")
_loaded = None


def _load_model():
    global _loaded
    if _loaded is None:
        path = USER_MODEL_PATH if os.path.isfile(USER_MODEL_PATH) else BASE_MODEL_PATH
        if not os.path.isfile(path):
            raise FileNotFoundError("No phishing classifier is installed. Upload a labeled 30-feature CSV to train one.")
        _loaded = joblib.load(path)
    return _loaded


def reload_model():
    """Reload the active model after an uploaded dataset has been trained."""
    global _loaded
    _loaded = None
    return _load_model()


def _model_and_columns(loaded):
    if isinstance(loaded, dict) and "model" in loaded:
        return (
            loaded["model"],
            list(loaded.get("feature_names", FEATURE_NAMES)),
            float(loaded.get("threshold", 0.65)),
            float(loaded.get("legitimate_threshold", 0.35)),
        )
    columns = list(getattr(loaded, "feature_names_in_", FEATURE_NAMES))
    return loaded, columns, 0.60, 0.40


def _phishing_probability(model, frame):
    if not hasattr(model, "predict_proba"):
        predicted = model.predict(frame)[0]
        return 1.0 if predicted == -1 else 0.0
    probabilities = model.predict_proba(frame)[0]
    classes = list(getattr(model, "classes_", []))
    if -1 in classes:
        return float(probabilities[classes.index(-1)])
    if 0 in classes and 1 in classes:
        # Training UI maps phishing to 1 and legitimate to 0.
        return float(probabilities[classes.index(1)])
    raise ValueError("The classifier labels must distinguish phishing and legitimate URLs.")


def predict_url(url):
    values = extract_features(url)
    loaded = _load_model()
    model, feature_names, threshold, legitimate_threshold = _model_and_columns(loaded)
    by_name = dict(zip(FEATURE_NAMES, values))
    unknown = [name for name in feature_names if name not in by_name]
    if unknown:
        raise ValueError(f"The installed model expects unsupported feature columns: {unknown}")

    row = [by_name[name] for name in feature_names]
    frame = pd.DataFrame([row], columns=feature_names)
    phishing_probability = _phishing_probability(model, frame)
    confidence = round(max(phishing_probability, 1 - phishing_probability) * 100, 2)
    prediction = -1 if phishing_probability >= threshold else 1 if phishing_probability <= legitimate_threshold else 0

    # The bundled historical model was trained with HTTPS as a feature. Check
    # whether that one transport signal alone changes its verdict. In that
    # case return an explicit inconclusive result instead of a phishing claim.
    if "HTTPS" in feature_names and prediction == -1:
        neutral_row = dict(zip(feature_names, row))
        neutral_row["HTTPS"] = 0
        neutral_probability = _phishing_probability(model, pd.DataFrame([neutral_row], columns=feature_names))
        if neutral_probability < threshold and phishing_probability - neutral_probability >= 0.15:
            prediction = 0

    return prediction, confidence
