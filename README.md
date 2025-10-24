# ThreatDetectX

**AI-Powered Cybersecurity Threat Detection and Enrichment Platform**

## Overview
ThreatDetectX is a cloud-native threat detection and enrichment platform that ingests security logs, applies AI-based anomaly detection, and enriches alerts using external threat intelligence sources. The goal is to showcase integration of AWS, AI/ML, and automation for modern cloud security.

## Features
- AWS CloudTrail / Zeek log ingestion
- AI/ML-based anomaly detection (Isolation Forest)
- Threat intelligence enrichment (AbuseIPDB / VirusTotal)
- Streamlit dashboard for visualization
- Terraform automation for AWS infrastructure

## Architecture
1. Data Ingestion Layer (AWS S3, CloudTrail)
2. Detection Engine (Lambda ML Model)
3. Threat Enrichment APIs
4. Streamlit Dashboard

## Tech Stack
- **Cloud:** AWS S3, Lambda, IAM  
- **IaC:** Terraform  
- **ML:** Python (scikit-learn, pandas)  
- **Dashboard:** Streamlit  
- **APIs:** AbuseIPDB, VirusTotal  

## Folder Structure
backend/ - ingestion, detection, enrichment modules
dashboard/ - Streamlit dashboard
infrastructure/ - Terraform templates
datasets/ - sample datasets
docs/ - documentation and architecture diagram

## Setup Instructions
1. Clone repo: `git clone https://github.com/suryarsc/ThreatDetectX.git`  
2. Create Python virtual environment  
3. Install dependencies from `backend/requirements.txt` and `dashboard/requirements.txt`  
4. Deploy infrastructure using Terraform  
5. Run dashboard: `streamlit run dashboard/app.py`  
