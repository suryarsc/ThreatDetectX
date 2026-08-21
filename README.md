# ThreatDetectX 🛡️

**AI-Powered Cybersecurity Threat Detection & Intelligence Enrichment Platform**

[![CI](https://github.com/suryarsc/ThreatDetectX/actions/workflows/ci.yml/badge.svg)](https://github.com/suryarsc/ThreatDetectX/actions/workflows/ci.yml)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)

ThreatDetectX is a cloud-native cybersecurity platform that automates security log ingestion, detects behavioral anomalies using unsupervised Machine Learning (Isolation Forest), and enriches suspicious network indicators with external Threat Intelligence (AbuseIPDB).

---

## 🌟 Key Features

- **Multi-Source Log Ingestion**: Ingests AWS CloudTrail Insight JSON logs, network telemetry CSVs, and raw security logs.
- **AI Anomaly Detection Engine**: Unsupervised Machine Learning model (`IsolationForest`) analyzing network session metadata (`duration`, `bytes_sent`, `bytes_received`, `packets`) to flag anomalous traffic and exfiltration attempts.
- **Threat Intelligence Enrichment**: Automated IP reputation scoring via the AbuseIPDB API with severity categorization (`CLEAN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Interactive SOC Analyst Dashboard**: Streamlit web console featuring real-time telemetry testing, drag-and-drop batch CSV scanning, threat distribution charts, and IP reputation lookup gauges.
- **AWS Infrastructure as Code**: Modular Terraform configuration to provision encrypted AWS S3 log buckets (`AES256`), lifecycle archival policies, and least-privilege IAM roles.

---

## 🏛️ System Architecture

```
                                  [ Security Telemetry Sources ]
                                (CloudTrail JSON / Network CSVs)
                                               │
                                               ▼
                              ┌───────────────────────────────────┐
                              │     Data Ingestion Layer (S3)     │
                              └─────────────────┬─────────────────┘
                                                │
                                                ▼
                              ┌───────────────────────────────────┐
                              │    AI Anomaly Detection Engine    │
                              │    Isolation Forest (Joblib ML)   │
                              └─────────────────┬─────────────────┘
                                                │ (Flagged Outliers)
                                                ▼
                              ┌───────────────────────────────────┐
                              │  Threat Intelligence Enrichment   │
                              │      AbuseIPDB Reputation API     │
                              └─────────────────┬─────────────────┘
                                                │
                                                ▼
          ┌─────────────────────────────────────┴─────────────────────────────────────┐
          │                                                                           │
          ▼                                                                           ▼
┌─────────────────────────────────┐                         ┌─────────────────────────────────┐
│     Flask REST API (:5000)      │ ◀─────────────────────▶ │   Streamlit Dashboard (:8501)   │
│  - /api/detect                  │                         │  - SOC Command Center           │
│  - /api/detect_batch            │                         │  - Live AI Anomaly Predictor    │
│  - /api/check_ip                │                         │  - Batch CSV Log Scanner        │
│  - /api/upload                  │                         │  - Threat Intel Gauge Widget    │
└─────────────────────────────────┘                         └─────────────────────────────────┘
```

---

## 🧰 Tech Stack

- **Backend API**: Python 3.11, Flask, Gunicorn / Werkzeug
- **Machine Learning**: Scikit-learn (`IsolationForest`), Pandas, NumPy, Joblib
- **Threat Intelligence**: AbuseIPDB REST API v2
- **Dashboard & UI**: Streamlit, Plotly Express & Graph Objects
- **Cloud & IaC**: AWS S3, IAM, Terraform (AWS Provider ~> 5.0)

---

## 📁 Repository Structure

```
ThreatDetectX/
├── backend/
│   ├── app.py                      # Flask REST API server
│   ├── Dockerfile                  # Backend container (gunicorn)
│   ├── data_ingestion/             # Log ingestion loaders
│   ├── detection_engine/           # Isolation Forest training and inference
│   │   ├── anomaly_detector.py     # Train / evaluate / predict helpers
│   │   ├── train.py                # Train + evaluate CLI (writes metrics.json)
│   │   └── model/                  # Serialized model (.joblib) + metrics.json
│   ├── enrichment/                 # Multi-source threat enrichment logic
│   ├── services/                   # AWS S3 and AbuseIPDB clients
│   └── requirements.txt            # Backend dependencies
├── dashboard/
│   ├── app.py                      # Streamlit SOC Analyst Web Application
│   ├── Dockerfile                  # Dashboard container (streamlit)
│   └── requirements.txt            # Dashboard dependencies
├── datasets/
│   ├── cloudtrail-sample/          # Sample AWS CloudTrail Insight logs
│   ├── generate_synthetic_logs.py  # Labeled synthetic telemetry generator
│   └── synthetic_logs.csv          # Network session telemetry dataset
├── tests/                          # Pytest unit + API integration suite
├── docs/                           # Detailed docs, architecture diagram
├── infrastructure/
│   └── terraform/                  # Terraform IaC templates (main, vars, outputs)
├── .github/workflows/ci.yml        # GitHub Actions CI (lint + train + test)
├── docker-compose.yml              # One-command local stack (API + dashboard)
├── requirements-dev.txt            # Dev/CI tools (pytest, ruff)
├── .env.example                    # Environment variable template
├── LICENSE                         # MIT License
└── README.md                       # Main project documentation
```

---

## 🚀 Quick Start Guide

### 1. Clone Repository & Setup Virtual Environment

```bash
git clone https://github.com/suryarsc/ThreatDetectX.git
cd ThreatDetectX

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt
pip install -r dashboard/requirements.txt
```

### 2. Configure Environment Variables

```bash
cp .env.example .env
```
Edit `.env` to configure your API keys (optional for local offline testing):
```env
ABUSEIPDB_KEY=your_abuseipdb_api_key_here
TDX_S3_BUCKET=your_s3_bucket_name
AWS_REGION=us-east-1
```

### 3. Start Backend REST API

```bash
python backend/app.py
```
*Backend runs at `http://127.0.0.1:5000`.*

### 4. Launch SOC Analyst Dashboard

```bash
streamlit run dashboard/app.py
```
*Open `http://localhost:8501` in your browser.*

---

## 🐳 Run with Docker

Bring up both the API and the dashboard with a single command:

```bash
docker compose up --build
```

- Backend API → `http://localhost:5000`
- Dashboard → `http://localhost:8501`

The dashboard reaches the backend automatically over the internal Docker network (`BACKEND_URL=http://backend:5000`). Set `ABUSEIPDB_KEY` in your shell (or a `.env` file) before `up` to enable live threat-intel lookups.

---

## 🤖 Model Performance

The Isolation Forest is trained **unsupervised** on network-session features, then evaluated against a held-out, labeled test split (labels are used for scoring only, never for training). Regenerate the dataset and retrain end-to-end with:

```bash
python datasets/generate_synthetic_logs.py --rows 2000 --anomaly-rate 0.08
python backend/detection_engine/train.py --data datasets/synthetic_logs.csv
```

Metrics on the 500-row held-out test set (see [`metrics.json`](backend/detection_engine/model/metrics.json)):

| Metric | Score |
| :--- | :--- |
| Precision | 0.95 |
| Recall | 0.98 |
| F1 | 0.96 |
| ROC-AUC | 1.00 |

> The bundled synthetic generator produces three realistic anomaly patterns — data-exfiltration bursts, low-and-slow beacons, and scan/flood traffic — so the model is exercised against distinct malicious behaviors rather than a single toy case.

---

## 🧪 Testing & Quality

The project ships with a **26-test pytest suite** (unit + Flask integration tests) and **ruff** linting, both enforced in CI on every push and pull request.

```bash
pip install -r requirements-dev.txt
ruff check backend tests datasets
pytest
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Health check and active endpoint catalog |
| `POST` | `/api/detect` | Predicts anomaly for single telemetry record with optional IP enrichment |
| `POST` | `/api/detect_batch` | Bulk anomaly detection across an array of telemetry objects |
| `POST` | `/api/check_ip` | AbuseIPDB threat intelligence reputation lookup for an IP |
| `POST` | `/api/upload` | Secure log file upload to S3 ingestion bucket |
| `POST` | `/api/enrich` | Enriches flagged security records with threat levels |

---

## ☁️ Deploy Infrastructure (Terraform)

```bash
cd infrastructure/terraform
terraform init
terraform plan
terraform apply
```

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for more information.
