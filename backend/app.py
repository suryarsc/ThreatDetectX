from flask import Flask, request, jsonify
from services.threat_intel import check_ip_reputation
from services.aws_s3 import upload_file_to_s3
from detection_engine.anomaly_detector import predict_single
import os

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({"message": "ThreatDetectX Backend Running"})

@app.route("/api/check_ip", methods=["POST"])
def check_ip():
    # Expects JSON: {"ip": "8.8.8.8"}
    data = request.get_json(force=True)
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "ip missing"}), 400

    result = check_ip_reputation(ip)
    return jsonify(result)

@app.route("/api/upload", methods=["POST"])
def upload():
    # Expects form-data file upload (file param = file)
    if "file" not in request.files:
        return jsonify({"error": "file missing"}), 400
    f = request.files["file"]
    filename = f.filename
    tmp_path = os.path.join("/tmp" if os.name != "nt" else ".", filename)
    f.save(tmp_path)

    # Bucket name must be created (we'll create via Terraform later)
    bucket = os.environ.get("TDX_S3_BUCKET")
    if not bucket:
        return jsonify({"error": "TDX_S3_BUCKET env var not set"}), 500

    s3_path = upload_file_to_s3(tmp_path, bucket, filename)
    return jsonify({"s3_path": s3_path})

@app.route("/api/detect", methods=["POST"])
def detect():
    """
    Expects JSON:
    {"duration": 10, "bytes_sent": 1200, "bytes_received": 800, "packets": 32}
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    required = ["duration", "bytes_sent", "bytes_received", "packets"]
    missing = [k for k in required if k not in data]
    if missing:
        return jsonify({"error": f"Missing keys: {missing}", "required": required}), 400

    try:
        record = {k: float(data[k]) for k in required}
        result = predict_single(record)
    except FileNotFoundError:
        return jsonify({"error": "Model not found. Train it first using anomaly_detector.py"}), 500
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500

    return jsonify(result)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
