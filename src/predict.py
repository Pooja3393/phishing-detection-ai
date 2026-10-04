import os
import joblib
import pandas as pd

# Load the trained model using script-relative path
current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, "..", "models", "phishing_model.pkl")
model = joblib.load(model_path)

print("=" * 60)
print("PHISHING WEBSITE DETECTOR")
print("=" * 60)

# Get all 30 feature values from the user
feature_names = [
    "UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//",
    "PrefixSuffix-", "SubDomains", "HTTPS", "DomainRegLen", "Favicon",
    "NonStdPort", "HTTPSDomainURL", "RequestURL", "AnchorURL",
    "LinksInScriptTags", "ServerFormHandler", "InfoEmail",
    "AbnormalURL", "WebsiteForwarding", "StatusBarCust",
    "DisableRightClick", "UsingPopupWindow", "IframeRedirection",
    "AgeofDomain", "DNSRecording", "WebsiteTraffic",
    "PageRank", "GoogleIndex", "LinksPointingToPage",
    "StatsReport"
]

user_input = []

print("\nEnter feature values (usually -1, 0, or 1)\n")

for feature in feature_names:
    value = int(input(f"{feature}: "))
    user_input.append(value)

# Convert to DataFrame
input_df = pd.DataFrame([user_input], columns=feature_names)

# Predict
prediction = model.predict(input_df)[0]

print("\n" + "=" * 60)

if prediction == -1:
    print("🚨 Prediction: PHISHING WEBSITE")
else:
    print("✅ Prediction: LEGITIMATE WEBSITE")

print("=" * 60)