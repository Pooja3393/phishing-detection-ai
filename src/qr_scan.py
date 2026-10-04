from qr_detector import decode_qr
from predict_url import predict_url
from drift_verifier import verify_url
from risk_engine import calculate_risk
from url_safety import normalize_url, UnsafeURLError


def scan_qr(image_path):

    # Step 1: Decode QR
    url, error = decode_qr(image_path)

    if error:
        return {
            "success": False,
            "error": error
        }

    # Step 2: Check whether extracted data is a URL
    try:
        url = normalize_url(url)
    except UnsafeURLError:
        return {
            "success": False,
            "error": "QR code does not contain a valid HTTP or HTTPS website URL.",
            "data": url
        }

    # Step 3: ML prediction
    prediction, confidence = predict_url(url)

    # Step 4: Active link verification
    drift = verify_url(url)

    # Step 5: Risk analysis
    score, risk, reasons = calculate_risk(
        url,
        prediction,
        drift,
        confidence
    )

    return {
        "success": True,
        "url": url,
        "prediction": prediction,
        "confidence": confidence,
        "drift": drift,
        "score": score,
        "risk": risk,
        "reasons": reasons
    }
