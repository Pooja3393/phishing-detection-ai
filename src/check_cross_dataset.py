import os
import sys
import pandas as pd

# Safe console encoding for Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

current_dir = os.path.dirname(os.path.abspath(__file__))
dataset_path = os.path.join(current_dir, "..", "dataset", "cross_channel_dataset.csv")

if not os.path.exists(dataset_path):
    print(f"Error: Dataset not found at {dataset_path}")
    sys.exit(1)

df = pd.read_csv(dataset_path)

print("=" * 60)
print("📊 CROSS-CHANNEL DATASET SUMMARY")
print("=" * 60)
print(f"Total Coupled Samples : {len(df)}")
print(f"Phishing Samples (1)  : {(df['is_phishing'] == 1).sum()}")
print(f"Legitimate Samples (0): {(df['is_phishing'] == 0).sum()}")
print()
print("Scenario Type Distribution:")
print(df["scenario_type"].value_counts().to_string())
print()
print("Unique Claimed Organizations:", df["claimed_org"].nunique())
print("Top Claimed Organizations:")
print(df["claimed_org"].value_counts().head(8).to_string())
print("=" * 60)
