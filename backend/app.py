import os

from detection_engine.anomaly_detector import predict_batch, predict_single
from enrichment.enrichment import enrich_record, enrich_threats
from flask import Flask, jsonify, request
from services.aws_s3 import upload_file_to_s3
from services.threat_intel import check_ip_reputation

app = Flask(__name__)

@app.route("/")
def home():
    return jsonify({
        "status": "healthy",
        "service": "ThreatDetectX Backend API",
        "version": "1.0.0",
        "endpoints": [
            "/api/check_ip",
            "/api/detect",
            "/api/detect_batch",
            "/api/enrich",
            "/api/upload"
        ]
    })

@app.route("/api/check_ip", methods=["POST"])
def check_ip():
    """
    Expects JSON: {"ip": "185.220.101.5"}
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "ip field is missing"}), 400

    result = check_ip_reputation(ip)
    return jsonify(result)

import tempfile

from werkzeug.utils import secure_filename


@app.route("/api/upload", methods=["POST"])
def upload():
    """
    Expects multipart/form-data with file field named 'file'.
    Uploads to configured AWS S3 bucket.
    """
    if "file" not in request.files:
        return jsonify({"error": "file missing in request"}), 400

    f = request.files["file"]
    filename = secure_filename(f.filename) if f.filename else ""
    if not filename:
        return jsonify({"error": "empty or invalid filename"}), 400

    upload_dir = os.path.join(tempfile.gettempdir(), "threatdetectx_uploads")
    os.makedirs(upload_dir, exist_ok=True)
    tmp_path = os.path.join(upload_dir, filename)
    f.save(tmp_path)

    bucket = os.environ.get("TDX_S3_BUCKET")
    if not bucket:
        return jsonify({
            "warning": "TDX_S3_BUCKET env var not set. Saved to temp storage.",
            "local_path": tmp_path,
            "filename": filename
        }), 200

    s3_path = upload_file_to_s3(tmp_path, bucket, filename)
    return jsonify({"s3_path": s3_path, "filename": filename})

@app.route("/api/detect", methods=["POST"])
def detect():
    """
    Expects JSON:
    {"duration": 10, "bytes_sent": 1200, "bytes_received": 800, "packets": 32,
     "ip": "185.220.101.5" (optional)}
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

        # Attach optional metadata and enrich if IP provided
        if "ip" in data:
            result["ip"] = data["ip"]
            result = enrich_record(result)

    except FileNotFoundError:
        return jsonify({"error": "Model not found. Train it first using anomaly_detector.py"}), 500
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500

    return jsonify(result)

@app.route("/api/detect_batch", methods=["POST"])
def detect_batch():
    """
    Expects JSON:
    {"records": [{"duration": 10, "bytes_sent": 1200, "bytes_received": 800, "packets": 32}, ...]}
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    records = data.get("records")
    if not records or not isinstance(records, list):
        return jsonify({"error": "'records' must be a non-empty list of objects"}), 400

    try:
        results = predict_batch(records)
        # Enrich anomalies that have IP addresses
        enriched_results = [enrich_record(r) for r in results]

        anomaly_count = sum(1 for r in enriched_results if r.get("is_anomaly"))
        return jsonify({
            "total_records": len(enriched_results),
            "anomaly_count": anomaly_count,
            "results": enriched_results
        })
    except Exception as e:
        return jsonify({"error": f"Batch prediction failed: {str(e)}"}), 500

@app.route("/api/enrich", methods=["POST"])
def enrich():
    """
    Expects JSON: {"records": [...]} or a single record dict
    """
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    if "records" in data and isinstance(data["records"], list):
        enriched = enrich_threats(data["records"])
        return jsonify({"results": enriched})
    else:
        enriched = enrich_record(data)
        return jsonify(enriched)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)
