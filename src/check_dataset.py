import os
import sys
import pandas as pd

# Script-relative paths
current_dir = os.path.dirname(os.path.abspath(__file__))
dataset_path = os.path.join(current_dir, "..", "dataset", "phishing.csv")
output_path = os.path.join(current_dir, "output.txt")

# Save output to a file
sys.stdout = open(output_path, "w", encoding="utf-8")

df = pd.read_csv(dataset_path)

print("=" * 50)
print("First 5 Rows")
print("=" * 50)
print(df.head())

print("\nDataset Shape:")
print(df.shape)

print("\nColumn Names:")
print(df.columns.tolist())

print("\nData Types:")
print(df.dtypes)

print("\nMissing Values:")
print(df.isnull().sum())

sys.stdout.close()