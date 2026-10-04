"""Command-line entry point for training from a labeled 30-feature CSV."""

import argparse
import os
import sys

import pandas as pd

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from model_training import inspect_dataset, train_uploaded_dataset


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", help="Path to a labeled URL-feature CSV")
    parser.add_argument("--phishing-label", required=True, help="Exact label value meaning phishing")
    arguments = parser.parse_args()

    frame = pd.read_csv(arguments.csv_path)
    target, _ = inspect_dataset(frame)
    bundle, path = train_uploaded_dataset(frame, target, arguments.phishing_label)
    print(f"Activated model: {bundle['model_name']}")
    print(f"Model file: {path}")
    for key, value in bundle["metrics"].items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
