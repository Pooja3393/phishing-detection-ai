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

from predict_url import predict_url

url = input("Enter URL: ")

prediction, confidence = predict_url(url)

print("\nPrediction:", prediction)
print("Confidence:", confidence, "%")

if prediction == -1:
    print("🚨 Phishing Website")
else:
    print("✅ Legitimate Website")