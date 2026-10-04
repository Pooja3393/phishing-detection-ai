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

from feature_extractor import extract_features

url = input("Enter URL: ")

features = extract_features(url)

print("\nExtracted Features:\n")

for i, value in enumerate(features, start=1):
    print(f"Feature {i}: {value}")