"""
Train and evaluate the ThreatDetectX IsolationForest anomaly detector.

Performs a stratified train/test split on a labeled dataset, fits the model
unsupervised on the training features, evaluates it on the held-out test set,
persists the model to detection_engine/model/, and writes a metrics report to
detection_engine/model/metrics.json.

Usage:
    python backend/detection_engine/train.py \
        --data datasets/synthetic_logs.csv --contamination 0.08
"""

import argparse
import json
import os

import pandas as pd
from anomaly_detector import FEATURES, MODEL_FILE, MODEL_PATH, ensure_model_dir, evaluate_model
from joblib import dump
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

METRICS_FILE = os.path.join(MODEL_PATH, "metrics.json")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train + evaluate the anomaly detector.")
    parser.add_argument("--data", default="datasets/synthetic_logs.csv")
    parser.add_argument("--contamination", type=float, default=0.08)
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    df = pd.read_csv(args.data)
    if "label" not in df.columns:
        raise SystemExit(
            "Dataset needs a `label` column (0/1) for evaluation. "
            "Regenerate with datasets/generate_synthetic_logs.py."
        )

    train_df, test_df = train_test_split(
        df, test_size=args.test_size, random_state=args.seed, stratify=df["label"]
    )

    model = IsolationForest(
        n_estimators=200, contamination=args.contamination, random_state=args.seed
    )
    model.fit(train_df[FEATURES])

    ensure_model_dir()
    dump(model, MODEL_FILE)

    metrics = {
        "model": "IsolationForest",
        "n_estimators": 200,
        "contamination": args.contamination,
        "features": FEATURES,
        "train_size": int(len(train_df)),
        "test": evaluate_model(model, test_df),
    }
    with open(METRICS_FILE, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    t = metrics["test"]
    print(f"[train] model saved to {MODEL_FILE}")
    print(f"[train] test set ({t['n_samples']} rows, {t['n_anomalies']} anomalies):")
    print(f"        precision={t['precision']}  recall={t['recall']}  "
          f"f1={t['f1']}  roc_auc={t['roc_auc']}")
    print(f"[train] metrics written to {METRICS_FILE}")


if __name__ == "__main__":
    main()
