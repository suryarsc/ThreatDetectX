import json
import os

import pandas as pd

# Resolve project root dynamically
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLOUDTRAIL_DIR = os.path.join(BASE_DIR, "datasets", "cloudtrail-sample")
SYNTHETIC_CSV_PATH = os.path.join(BASE_DIR, "datasets", "synthetic_logs.csv")

def load_cloudtrail_logs(dataset_dir=None):
    """Load all JSON formatted CloudTrail log files from the dataset directory."""
    target_dir = dataset_dir or CLOUDTRAIL_DIR
    logs = []
    if not os.path.exists(target_dir):
        return logs

    for filename in os.listdir(target_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(target_dir, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                logs.append(json.load(f))
    return logs

def load_synthetic_logs(csv_path=None):
    """Load synthetic network telemetry CSV dataset."""
    target_path = csv_path or SYNTHETIC_CSV_PATH
    if not os.path.exists(target_path):
        return pd.DataFrame()
    return pd.read_csv(target_path)

if __name__ == "__main__":
    ct_logs = load_cloudtrail_logs()
    print(f"Loaded {len(ct_logs)} CloudTrail log file(s)")
    syn_df = load_synthetic_logs()
    print(f"Loaded synthetic dataset with shape: {syn_df.shape}")
