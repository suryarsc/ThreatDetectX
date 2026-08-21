import os

import pandas as pd
from joblib import dump, load
from sklearn.ensemble import IsolationForest

MODEL_FILENAME = "isolation_forest_model.joblib"
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model")
MODEL_FILE = os.path.join(MODEL_PATH, MODEL_FILENAME)

def ensure_model_dir():
    if not os.path.exists(MODEL_PATH):
        os.makedirs(MODEL_PATH, exist_ok=True)

FEATURES = ["duration", "bytes_sent", "bytes_received", "packets"]


def train_model(dataset_csv_path, contamination=0.08):
    """
    Train an Isolation Forest on the CSV and save the model.

    dataset_csv_path: CSV with feature columns duration, bytes_sent,
        bytes_received, packets. An optional `label` column (0/1) is ignored
        for training (the model is unsupervised) but may be used by
        `evaluate_model` for scoring.
    contamination: expected proportion of anomalies; should approximate the
        real anomaly rate of the data.
    """
    ensure_model_dir()
    df = pd.read_csv(dataset_csv_path)
    X = df[FEATURES]
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    model.fit(X)
    dump(model, MODEL_FILE)
    print(f"[anomaly_detector] model trained on {len(X)} rows and saved to {MODEL_FILE}")
    return MODEL_FILE


def evaluate_model(model, df):
    """
    Evaluate a trained model against a labeled DataFrame.

    Requires a `label` column (0 = normal, 1 = anomaly). Returns a dict of
    precision / recall / f1 / roc_auc for the anomaly class. Import of
    sklearn.metrics is local so the API runtime does not pay for it.
    """
    from sklearn.metrics import precision_recall_fscore_support, roc_auc_score

    X = df[FEATURES]
    y_true = df["label"].astype(int).to_numpy()
    y_pred = (model.predict(X) == -1).astype(int)          # 1 == flagged anomaly
    # decision_function: higher = more normal; negate so higher = more anomalous
    anomaly_scores = -model.decision_function(X)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )
    try:
        roc_auc = roc_auc_score(y_true, anomaly_scores)
    except ValueError:
        roc_auc = float("nan")

    return {
        "n_samples": int(len(df)),
        "n_anomalies": int(y_true.sum()),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
    }

def load_model():
    if not os.path.exists(MODEL_FILE):
        raise FileNotFoundError(f"Model not found at {MODEL_FILE}. Train it first.")
    return load(MODEL_FILE)

def predict_single(record_dict):
    """
    record_dict: e.g. {"duration": 10, "bytes_sent": 1200, ...}
    returns: dict { "prediction": "anomalous"/"normal", "score": <raw score> }
    """
    model = load_model()
    features = ["duration", "bytes_sent", "bytes_received", "packets"]
    df = pd.DataFrame([record_dict])[features]
    pred = model.predict(df)[0]        # -1 for anomaly, 1 for normal
    # decision_function: anomaly score; lower = more abnormal
    score = float(model.decision_function(df)[0])
    return {
        "prediction": "anomalous" if pred == -1 else "normal",
        "score": round(score, 4),
        "is_anomaly": bool(pred == -1)
    }

def predict_batch(records_list):
    """
    records_list: list of dicts or DataFrame containing the required features
    returns: list of dicts with original data + predictions and anomaly scores
    """
    model = load_model()
    features = ["duration", "bytes_sent", "bytes_received", "packets"]

    if isinstance(records_list, pd.DataFrame):
        df = records_list.copy()
    else:
        df = pd.DataFrame(records_list)

    for col in features:
        if col not in df.columns:
            raise ValueError(f"Missing required feature column: {col}")

    feature_df = df[features].astype(float)
    preds = model.predict(feature_df)
    scores = model.decision_function(feature_df)

    results = []
    for i in range(len(df)):
        row_dict = df.iloc[i].to_dict()
        row_dict["prediction"] = "anomalous" if preds[i] == -1 else "normal"
        row_dict["anomaly_score"] = round(float(scores[i]), 4)
        row_dict["is_anomaly"] = bool(preds[i] == -1)
        results.append(row_dict)

    return results
