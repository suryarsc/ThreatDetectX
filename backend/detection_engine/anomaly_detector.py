import os
import pandas as pd
from sklearn.ensemble import IsolationForest
from joblib import dump, load

MODEL_FILENAME = "isolation_forest_model.joblib"
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model")
MODEL_FILE = os.path.join(MODEL_PATH, MODEL_FILENAME)

def ensure_model_dir():
    if not os.path.exists(MODEL_PATH):
        os.makedirs(MODEL_PATH, exist_ok=True)

def train_model(dataset_csv_path, contamination=0.2):
    """
    Train an Isolation Forest on the CSV and save the model.
    dataset_csv_path: path to CSV with columns: duration, bytes_sent, bytes_received, packets
    """
    ensure_model_dir()
    df = pd.read_csv(dataset_csv_path)
    features = ["duration", "bytes_sent", "bytes_received", "packets"]
    X = df[features]
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(X)
    dump(model, MODEL_FILE)
    print(f"[anomaly_detector] model trained and saved to {MODEL_FILE}")
    return MODEL_FILE

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
    df = pd.DataFrame([record_dict])
    pred = model.predict(df)[0]        # -1 for anomaly, 1 for normal
    # decision_function: anomaly score; lower = more abnormal
    score = float(model.decision_function(df)[0])
    return {"prediction": "anomalous" if pred == -1 else "normal", "score": score}
