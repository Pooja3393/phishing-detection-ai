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

from qr_detector import decode_qr

image_path = input("Enter QR image path: ")

data, error = decode_qr(image_path)

if error:
    print("❌", error)
else:
    print("=" * 50)
    print("QR CODE DETECTED")
    print("=" * 50)

    print("Extracted Data:")
    print(data)