import os
import sys

# Ensure src directory is in sys.path
src_dir = os.path.dirname(os.path.abspath(__file__))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

# Ensure safe UTF-8 console output on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from qr_scan import scan_qr


image_path = input("Enter QR image path: ")

result = scan_qr(image_path)


if not result["success"]:

    print()
    print("❌ QR SCAN FAILED")
    print(result["error"])

    if "data" in result:
        print("Extracted Data:", result["data"])

else:

    print("=" * 60)
    print("🛡️ QR SECURITY SCAN")
    print("=" * 60)

    print()
    print("Extracted URL:")
    print(result["url"])

    print()
    print("ML Prediction:")

    if result["prediction"] == -1:
        print("🚨 PHISHING WEBSITE")
    else:
        print("✅ LEGITIMATE WEBSITE")

    print()
    print("Confidence:")
    print(str(result["confidence"]) + "%")

    print()
    print("Active Link Status:")
    print(result["drift"]["status"])

    print()
    print("HTTP Code:")
    print(result["drift"]["code"])

    print()
    print("Risk Score:")
    print(str(result["score"]) + "/100")

    print()
    print("Risk Level:")
    print(result["risk"])

    print()
    print("Reasons:")

    if len(result["reasons"]) == 0:
        print("No suspicious characteristics found.")

    else:
        for reason in result["reasons"]:
            print("•", reason)