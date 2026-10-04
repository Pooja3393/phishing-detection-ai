import sys
import os

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

from ai_explainer import explain_url


url = "https://example.com"

prediction = 1
confidence = 86.0

risk_score = 15
risk_level = "Low"

reasons = [
    "Website is using HTTPS."
]

drift = {
    "status": "Active",
    "code": 200,
    "risk": "Low"
}


result = explain_url(
    url=url,
    prediction=prediction,
    confidence=confidence,
    risk_score=risk_score,
    risk_level=risk_level,
    reasons=reasons,
    drift=drift
)


print()
print("🤖 AI URL SECURITY EXPLANATION")
print("=" * 50)
print(result)