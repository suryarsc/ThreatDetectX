# ThreatDetectX Technical Documentation

## 1. System Overview
ThreatDetectX is an AI-powered cybersecurity platform that combines automated security log ingestion, unsupervised Machine Learning anomaly detection, and Threat Intelligence enrichment to detect malicious or abnormal activity in real time.

```
+-------------------------------------------------------------------+
|                        Data Ingestion Layer                       |
|  - AWS CloudTrail Logs (JSON)                                     |
|  - Network Flow Telemetry (CSV)                                   |
|  - S3 Storage Ingestion (boto3)                                   |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|                      AI Detection Engine                          |
|  - Algorithm: Isolation Forest (scikit-learn)                     |
|  - Features: duration, bytes_sent, bytes_received, packets        |
|  - Model Persistence: joblib serialized model                     |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|                  Threat Intelligence Enrichment                   |
|  - AbuseIPDB Reputation API                                       |
|  - Severity Scoring: CLEAN, LOW, MEDIUM, HIGH, CRITICAL           |
+---------------------------------+---------------------------------+
                                  |
                                  v
+---------------------------------+---------------------------------+
|                       Presentation Layer                          |
|  - REST API: Flask (Port 5000)                                    |
|  - SOC Dashboard: Streamlit (Port 8501)                           |
+-------------------------------------------------------------------+
```

---

## 2. Machine Learning Anomaly Detection Model

### Model Architecture
- **Model Type:** Isolation Forest (`sklearn.ensemble.IsolationForest`)
- **Estimators:** 100 decision trees
- **Contamination:** 0.2 (assumes ~20% anomaly threshold)
- **Features Used:**
  - `duration`: Session duration in seconds
  - `bytes_sent`: Outbound bytes
  - `bytes_received`: Inbound bytes
  - `packets`: Total packet count transferred

### Decision Function
The model calculates an anomaly score for each session:
- **Score > 0:** Regular baseline activity (`normal`)
- **Score < 0:** Statistical outlier indicating suspicious data exfiltration, port scanning, or flood attacks (`anomalous`)

---

## 3. REST API Reference

The backend Flask API operates on `http://127.0.0.1:5000`.

### `GET /`
Health check and endpoint listing.
```json
{
  "status": "healthy",
  "service": "ThreatDetectX Backend API",
  "version": "1.0.0"
}
```

### `POST /api/detect`
Perform anomaly detection on a single telemetry record.
- **Request Body:**
```json
{
  "duration": 12,
  "bytes_sent": 3400,
  "bytes_received": 1200,
  "packets": 45,
  "ip": "185.220.101.5"
}
```
- **Response Body:**
```json
{
  "prediction": "anomalous",
  "score": -0.0824,
  "is_anomaly": true,
  "threat_level": "CRITICAL",
  "threat_intel": {
    "ip": "185.220.101.5",
    "abuse_confidence_score": 85,
    "isp": "DataCenter Transit",
    "country_code": "RU",
    "total_reports": 42
  }
}
```

### `POST /api/detect_batch`
Perform bulk anomaly detection on an array of telemetry records.
- **Request Body:**
```json
{
  "records": [
    {"duration": 10, "bytes_sent": 1200, "bytes_received": 800, "packets": 32},
    {"duration": 3, "bytes_sent": 15000, "bytes_received": 20000, "packets": 150, "ip": "185.220.101.5"}
  ]
}
```

### `POST /api/check_ip`
Query AbuseIPDB threat intelligence database for an IP address.
- **Request Body:** `{"ip": "185.220.101.5"}`

### `POST /api/upload`
Upload a security log file to the configured AWS S3 bucket.
- **Form Data:** `file=@Sample_Logs.json`

---

## 4. Terraform Cloud Infrastructure

The Terraform configurations in `infrastructure/terraform/` provision:
- **AWS S3 Bucket:** Private encrypted bucket with AES256 server-side encryption and public access blocks.
- **Lifecycle Policies:** Automatic transition of aged security logs to `STANDARD_IA` (30 days) and `GLACIER` (90 days).
- **IAM Role & Policies:** Least-privilege role for backend log ingestion.

### Deployment Commands
```bash
cd infrastructure/terraform
terraform init
terraform plan
terraform apply
```

---

## 5. Local Setup & Execution Guide

### Prerequisites
- Python 3.10+
- Virtual environment activated (`.venv` or `backend/venv`)

### 1. Start Backend API
```bash
python backend/app.py
```

### 2. Start Streamlit Dashboard
```bash
streamlit run dashboard/app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.
