import os
import json

DATASET_DIR = "D:\ThreatDetectX\datasets\cloudtrail-sample"

def load_logs():
    logs = []
    for filename in os.listdir(DATASET_DIR):
        if filename.endswith(".json"):
            with open(os.path.join(DATASET_DIR, filename)) as f:
                logs.append(json.load(f))
    return logs

if __name__ == "__main__":
    logs = load_logs()
    print(f"Loaded {len(logs)} log files")
