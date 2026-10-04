
import os
import cv2
import joblib
import numpy as np

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(CURRENT_DIR, "..", "models", "visual_hog_svm.pkl")

_model_bundle = None


def _load_model():
    global _model_bundle
    if _model_bundle is None:
        _model_bundle = joblib.load(MODEL_PATH)
    return _model_bundle


def _hog_features(image_path, image_size=(128, 128)):
    if not hasattr(cv2, "HOGDescriptor"):
        module_path = getattr(cv2, "__file__", "unknown path")
        raise RuntimeError(
            "OpenCV is incomplete or conflicting (cv2.HOGDescriptor is missing). "
            f"Python loaded cv2 from {module_path}. In the app's activated .venv, remove all OpenCV variants, "
            "install the single opencv-python package from requirements.txt, and restart Streamlit."
        )
    image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
    if image is None:
        raise ValueError("Could not read the screenshot image.")

    image = cv2.resize(image, image_size)

    hog = cv2.HOGDescriptor(
        (128, 128),
        (16, 16),
        (8, 8),
        (8, 8),
        9
    )

    return hog.compute(image).ravel().reshape(1, -1)


def detect_visual_phishing(image_path):
    """
    Baseline Phase-4 visual phishing detector.

    Uses HOG image features + LinearSVC trained on the supplied
    phase4_dataset. This is a baseline classifier, not a proof
    that an image is malicious.
    """
    bundle = _load_model()
    model = bundle["model"]
    image_size = tuple(bundle.get("image_size", (128, 128)))

    features = _hog_features(image_path, image_size)
    prediction = int(model.predict(features)[0])

    # LinearSVC has no predict_proba. Convert decision distance into
    # a bounded confidence-like score for UI display. It is not a
    # calibrated probability.
    decision = float(model.decision_function(features)[0])
    confidence = float(100.0 / (1.0 + np.exp(-abs(decision))))

    if prediction == 1:
        result = "Phishing"
        risk = "High"
        score = max(50, round(confidence))
    else:
        result = "Likely Legitimate"
        risk = "Low"
        score = max(0, round(100 - confidence))

    reasons = [
        "Visual classifier analyzed the uploaded screenshot.",
        "Prediction is based on HOG image features and a LinearSVC baseline model.",
        "Visual classification is an additional signal and should not be treated as absolute proof."
    ]

    return {
        "prediction": prediction,
        "result": result,
        "risk": risk,
        "score": score,
        "confidence": round(confidence, 2),
        "decision_value": round(decision, 4),
        "reasons": reasons
    }
