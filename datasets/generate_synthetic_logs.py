"""
Synthetic network-telemetry generator for ThreatDetectX.

Produces a labeled dataset of network sessions with a realistic mix of
"normal" traffic and injected anomalies (data-exfiltration style bursts,
long-lived low-volume beacons, and scan-like high-packet sessions).

The `label` column (0 = normal, 1 = anomaly) is ground truth used ONLY for
model evaluation — the IsolationForest itself trains unsupervised on the four
feature columns and never sees the label.

Usage:
    python datasets/generate_synthetic_logs.py --rows 2000 --anomaly-rate 0.08
"""

import argparse

import numpy as np
import pandas as pd

FEATURES = ["duration", "bytes_sent", "bytes_received", "packets"]


def generate(n_rows: int = 2000, anomaly_rate: float = 0.08, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    n_anom = int(n_rows * anomaly_rate)
    n_norm = n_rows - n_anom

    # --- Normal traffic: short-to-medium sessions, moderate byte volumes ---
    normal = pd.DataFrame({
        "duration": rng.gamma(shape=2.0, scale=6.0, size=n_norm).clip(1, 300),
        "bytes_sent": rng.gamma(shape=2.0, scale=900.0, size=n_norm).clip(50, 40000),
        "bytes_received": rng.gamma(shape=2.0, scale=700.0, size=n_norm).clip(50, 40000),
        "packets": rng.gamma(shape=2.0, scale=18.0, size=n_norm).clip(2, 400),
    })
    normal["label"] = 0

    # --- Anomalies: three distinct malicious patterns ---
    kinds = rng.integers(0, 3, size=n_anom)
    dur, snt, rcv, pkt = [], [], [], []
    for k in kinds:
        if k == 0:  # exfiltration: huge bytes_sent, low received
            dur.append(rng.uniform(2, 20))
            snt.append(rng.uniform(60000, 250000))
            rcv.append(rng.uniform(100, 3000))
            pkt.append(rng.uniform(120, 400))
        elif k == 1:  # low-and-slow beacon: long duration, tiny volume
            dur.append(rng.uniform(200, 300))
            snt.append(rng.uniform(50, 400))
            rcv.append(rng.uniform(50, 400))
            pkt.append(rng.uniform(2, 12))
        else:  # scan/flood: very high packet count, short duration
            dur.append(rng.uniform(1, 8))
            snt.append(rng.uniform(2000, 15000))
            rcv.append(rng.uniform(500, 5000))
            pkt.append(rng.uniform(600, 2000))
    anomalies = pd.DataFrame({
        "duration": dur, "bytes_sent": snt, "bytes_received": rcv, "packets": pkt,
    })
    anomalies["label"] = 1

    df = pd.concat([normal, anomalies], ignore_index=True)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df[FEATURES] = df[FEATURES].round(0).astype(int)
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic network telemetry.")
    parser.add_argument("--rows", type=int, default=2000)
    parser.add_argument("--anomaly-rate", type=float, default=0.08)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default="datasets/synthetic_logs.csv")
    args = parser.parse_args()

    df = generate(args.rows, args.anomaly_rate, args.seed)
    df.to_csv(args.out, index=False)
    print(f"[generate] wrote {len(df)} rows to {args.out} "
          f"({int(df['label'].sum())} anomalies, {df['label'].mean():.1%})")


if __name__ == "__main__":
    main()
