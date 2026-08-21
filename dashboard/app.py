import streamlit as st
import pandas as pd
import requests
import json
import os
import plotly.express as px
import plotly.graph_objects as go

# Set page config
st.set_page_config(
    page_title="ThreatDetectX | AI-Powered Threat Detection & Enrichment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #64748B;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #0F172A;
        color: #F8FAFC;
        padding: 1.2rem;
        border-radius: 10px;
        border-left: 5px solid #3B82F6;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .threat-badge-critical {
        background-color: #EF4444;
        color: white;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    .threat-badge-high {
        background-color: #F97316;
        color: white;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    .threat-badge-medium {
        background-color: #FBBF24;
        color: black;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: bold;
        font-size: 0.85rem;
    }
    .threat-badge-clean {
        background-color: #10B981;
        color: white;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: bold;
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to check backend API
def check_backend_health(base_url):
    try:
        r = requests.get(f"{base_url}/", timeout=2)
        if r.status_code == 200:
            return True, r.json()
        return False, {"error": f"Status code: {r.status_code}"}
    except Exception as e:
        return False, {"error": str(e)}

# Sidebar Configuration
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("ThreatDetectX")
    st.caption("AI-Powered Threat Detection & Enrichment")
    st.divider()

    st.subheader("⚙️ API Configuration")
    default_backend = os.environ.get("BACKEND_URL", "http://127.0.0.1:5000")
    backend_url = st.text_input("Backend API Endpoint", value=default_backend)
    
    is_healthy, health_data = check_backend_health(backend_url)
    if is_healthy:
        st.success("🟢 Backend Connected")
    else:
        st.error("🔴 Backend Disconnected")
        st.caption("Make sure `python backend/app.py` is running.")

    st.divider()
    app_mode = st.radio(
        "Navigation",
        [
            "🛡️ SOC Command Center",
            "🧠 AI Anomaly Detection",
            "🌐 Threat Intel Lookup (AbuseIPDB)",
            "☁️ Cloud Ingestion & S3 Manager",
            "📖 Architecture & Model Info"
        ]
    )

    st.divider()
    st.caption("ThreatDetectX v1.0.0 • Cloud & AI SecOps")

# -------------------------------------------------------------
# TAB 1: SOC COMMAND CENTER
# -------------------------------------------------------------
if app_mode == "🛡️ SOC Command Center":
    st.markdown('<div class="main-header">🛡️ SOC Command Center</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Live Security Telemetry Overview, Anomaly Metrics, and Threat Indicators</div>', unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="📊 Monitored Events", value="1,248", delta="+12% today")
    with col2:
        st.metric(label="⚠️ Flagged Anomalies", value="42", delta="3.3% anomaly rate", delta_color="inverse")
    with col3:
        st.metric(label="🚨 High/Critical Threats", value="7", delta="AbuseIPDB enriched", delta_color="inverse")
    with col4:
        engine_status = "Active (Isolation Forest)" if is_healthy else "Offline"
        st.metric(label="🤖 Detection Engine", value=engine_status)

    st.markdown("---")

    col_feed, col_chart = st.columns([3, 2])

    with col_feed:
        st.subheader("🚨 Recent High-Risk Detections")
        sample_feed = [
            {"Time": "14:12:05", "Source IP": "185.220.101.5", "Bytes Sent": "15,200", "Packets": "150", "Anomaly": "Anomalous", "Threat Level": "CRITICAL", "Score": "85%"},
            {"Time": "14:08:22", "Source IP": "194.26.29.112", "Bytes Sent": "10,400", "Packets": "130", "Anomaly": "Anomalous", "Threat Level": "HIGH", "Score": "64%"},
            {"Time": "13:55:10", "Source IP": "45.154.255.89", "Bytes Sent": "6,500", "Packets": "65", "Anomaly": "Anomalous", "Threat Level": "MEDIUM", "Score": "35%"},
            {"Time": "13:42:01", "Source IP": "10.0.1.45", "Bytes Sent": "800", "Packets": "20", "Anomaly": "Normal", "Threat Level": "CLEAN", "Score": "0%"},
            {"Time": "13:30:18", "Source IP": "192.168.1.100", "Bytes Sent": "250", "Packets": "10", "Anomaly": "Normal", "Threat Level": "CLEAN", "Score": "0%"},
        ]
        df_feed = pd.DataFrame(sample_feed)
        st.dataframe(df_feed, use_container_width=True, hide_index=True)

    with col_chart:
        st.subheader("📈 Threat Severity Breakdown")
        fig_pie = px.pie(
            values=[70, 15, 10, 5],
            names=["Clean / Normal", "Low / Medium", "High", "Critical"],
            color_discrete_sequence=["#10B981", "#FBBF24", "#F97316", "#EF4444"],
            hole=0.45
        )
        fig_pie.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=280)
        st.plotly_chart(fig_pie, use_container_width=True)

# -------------------------------------------------------------
# TAB 2: AI ANOMALY DETECTION
# -------------------------------------------------------------
elif app_mode == "🧠 AI Anomaly Detection":
    st.markdown('<div class="main-header">🧠 AI Anomaly Detection Engine</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Evaluate network traffic telemetry using Isolation Forest ML model</div>', unsafe_allow_html=True)

    tab_single, tab_batch = st.tabs(["🎯 Single Telemetry Inference", "📁 Batch CSV Scanner"])

    with tab_single:
        st.markdown("#### Input Network Session Telemetry")
        c1, c2 = st.columns(2)
        with c1:
            duration = st.slider("Connection Duration (seconds)", min_value=1, max_value=300, value=12)
            bytes_sent = st.number_input("Bytes Sent", min_value=0, max_value=500000, value=3400, step=100)
            src_ip = st.text_input("Source IP Address (Optional for Enrichment)", value="185.220.101.5")
        with c2:
            bytes_received = st.number_input("Bytes Received", min_value=0, max_value=500000, value=1200, step=100)
            packets = st.number_input("Packet Count", min_value=1, max_value=10000, value=45, step=5)

        if st.button("🚀 Analyze Telemetry with AI Model", type="primary"):
            payload = {
                "duration": duration,
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_received,
                "packets": packets
            }
            if src_ip.strip():
                payload["ip"] = src_ip.strip()

            try:
                res = requests.post(f"{backend_url}/api/detect", json=payload, timeout=10)
                if res.status_code == 200:
                    data = res.json()
                    st.success("✅ Analysis Complete")
                    
                    res_col1, res_col2, res_col3 = st.columns(3)
                    with res_col1:
                        is_anom = data.get("is_anomaly", False) or data.get("prediction") == "anomalous"
                        if is_anom:
                            st.error("🚨 Result: **ANOMALOUS ACTIVITY**")
                        else:
                            st.success("🟢 Result: **NORMAL ACTIVITY**")
                    with res_col2:
                        st.metric("Raw Anomaly Score", f"{data.get('score', 0):.4f}")
                        st.caption("Lower scores indicate abnormal deviation from baseline")
                    with res_col3:
                        threat_lvl = data.get("threat_level", "N/A")
                        st.metric("Threat Level", threat_lvl)

                    if "threat_intel" in data and data["threat_intel"]:
                        intel = data["threat_intel"]
                        st.markdown("##### 🌐 Threat Intelligence Enrichment")
                        intel_c1, intel_c2, intel_c3, intel_c4 = st.columns(4)
                        intel_c1.metric("Abuse Confidence", f"{intel.get('abuse_confidence_score', 0)}%")
                        intel_c2.metric("ISP", str(intel.get("isp", "N/A")))
                        intel_c3.metric("Country", str(intel.get("country_code", "N/A")))
                        intel_c4.metric("Reports", str(intel.get("total_reports", 0)))
                else:
                    st.error(f"Error {res.status_code}: {res.text}")
            except Exception as e:
                st.error(f"Failed to connect to backend: {str(e)}")

    with tab_batch:
        st.markdown("#### Bulk Security Log Analyzer")
        uploaded_file = st.file_uploader("Upload CSV Log File (Required columns: duration, bytes_sent, bytes_received, packets)", type=["csv"])
        
        load_sample = st.button("📄 Load Synthetic Dataset Sample")

        target_df = None
        if uploaded_file is not None:
            target_df = pd.read_csv(uploaded_file)
        elif load_sample:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            sample_path = os.path.join(base_dir, "datasets", "synthetic_logs.csv")
            if os.path.exists(sample_path):
                target_df = pd.read_csv(sample_path)
                st.info("Loaded `datasets/synthetic_logs.csv`")
            else:
                st.warning("Sample dataset not found locally.")

        if target_df is not None:
            st.write("##### Raw Dataset Preview", target_df.head(10))
            
            if st.button("⚡ Run Batch AI Anomaly Detection", type="primary"):
                records = target_df.to_dict(orient="records")
                try:
                    res = requests.post(f"{backend_url}/api/detect_batch", json={"records": records}, timeout=15)
                    if res.status_code == 200:
                        batch_res = res.json()
                        result_df = pd.DataFrame(batch_res["results"])
                        
                        m1, m2, m3 = st.columns(3)
                        m1.metric("Total Records Analyzed", batch_res.get("total_records", len(result_df)))
                        m2.metric("Anomalies Detected", batch_res.get("anomaly_count", 0))
                        anom_pct = (batch_res.get("anomaly_count", 0) / len(result_df)) * 100 if len(result_df) > 0 else 0
                        m3.metric("Anomaly Ratio", f"{anom_pct:.1f}%")

                        st.write("##### 📊 Analyzed Results", result_df)

                        # Plotly visual charts
                        c_chart1, c_chart2 = st.columns(2)
                        with c_chart1:
                            fig_scatter = px.scatter(
                                result_df,
                                x="bytes_sent",
                                y="bytes_received",
                                color="prediction",
                                size="packets",
                                hover_data=["duration", "anomaly_score"],
                                color_discrete_map={"anomalous": "#EF4444", "normal": "#10B981"},
                                title="Network Bytes Sent vs Received (Colored by Anomaly Prediction)"
                            )
                            st.plotly_chart(fig_scatter, use_container_width=True)

                        with c_chart2:
                            fig_hist = px.histogram(
                                result_df,
                                x="anomaly_score",
                                color="prediction",
                                nbins=20,
                                color_discrete_map={"anomalous": "#EF4444", "normal": "#10B981"},
                                title="Anomaly Score Distribution"
                            )
                            st.plotly_chart(fig_hist, use_container_width=True)

                        # CSV Download
                        csv_data = result_df.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            "📥 Download Analyzed Results CSV",
                            data=csv_data,
                            file_name="threatdetectx_analyzed_results.csv",
                            mime="text/csv"
                        )
                    else:
                        st.error(f"Batch detection failed ({res.status_code}): {res.text}")
                except Exception as e:
                    st.error(f"Error during batch processing: {str(e)}")

# -------------------------------------------------------------
# TAB 3: THREAT INTEL LOOKUP (ABUSEIPDB)
# -------------------------------------------------------------
elif app_mode == "🌐 Threat Intel Lookup (AbuseIPDB)":
    st.markdown('<div class="main-header">🌐 Threat Intelligence Reputation Lookup</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Query IP addresses against AbuseIPDB to determine reputation and malicious activity reports</div>', unsafe_allow_html=True)

    st.markdown("##### Quick IP Presets:")
    q_col1, q_col2, q_col3, q_col4 = st.columns(4)
    target_search_ip = "185.220.101.5"
    if q_col1.button("🚨 185.220.101.5 (Suspicious)"):
        target_search_ip = "185.220.101.5"
    if q_col2.button("⚠️ 194.26.29.112 (Scanner)"):
        target_search_ip = "194.26.29.112"
    if q_col3.button("🟢 8.8.8.8 (Google DNS)"):
        target_search_ip = "8.8.8.8"
    if q_col4.button("🟢 1.1.1.1 (Cloudflare)"):
        target_search_ip = "1.1.1.1"

    query_ip = st.text_input("Enter IP Address to Investigate", value=target_search_ip)

    if st.button("🔍 Check Threat Reputation", type="primary"):
        if not query_ip.strip():
            st.warning("Please enter a valid IP address.")
        else:
            try:
                res = requests.post(f"{backend_url}/api/check_ip", json={"ip": query_ip.strip()}, timeout=10)
                if res.status_code == 200:
                    intel = res.json()
                    st.success(f"Reputation Report for **{query_ip}**")

                    if intel.get("offline_mode"):
                        st.info("💡 Note: Running in local evaluation mode (Set `ABUSEIPDB_KEY` in `.env` for live API queries).")

                    # Threat Gauge
                    score = intel.get("abuse_confidence_score", 0)
                    threat_level = intel.get("threat_level", "CLEAN")

                    col_gauge, col_details = st.columns([2, 3])

                    with col_gauge:
                        fig_gauge = go.Figure(go.Indicator(
                            mode="gauge+number",
                            value=score,
                            title={"text": f"Abuse Confidence ({threat_level})"},
                            gauge={
                                "axis": {"range": [0, 100]},
                                "bar": {"color": "#EF4444" if score > 50 else ("#FBBF24" if score > 20 else "#10B981")},
                                "steps": [
                                    {"range": [0, 20], "color": "#E6F4EA"},
                                    {"range": [20, 50], "color": "#FEF3C7"},
                                    {"range": [50, 80], "color": "#FFEDD5"},
                                    {"range": [80, 100], "color": "#FEE2E2"}
                                ]
                            }
                        ))
                        fig_gauge.update_layout(height=280, margin=dict(t=30, b=10, l=20, r=20))
                        st.plotly_chart(fig_gauge, use_container_width=True)

                    with col_details:
                        st.write("##### Intelligence Details")
                        d1, d2 = st.columns(2)
                        d1.write(f"**ISP:** {intel.get('isp', 'Unknown')}")
                        d1.write(f"**Country Code:** {intel.get('country_code', 'Unknown')}")
                        d1.write(f"**Usage Type:** {intel.get('usage_type', 'Unknown')}")
                        
                        d2.write(f"**Total Reports:** {intel.get('total_reports', 0)}")
                        d2.write(f"**Whitelisted:** {intel.get('is_whitelisted', False)}")
                        d2.write(f"**Last Reported:** {intel.get('last_reported_at', 'None')}")

                    with st.expander("📄 View Raw API Response"):
                        st.json(intel)
                else:
                    st.error(f"API Error ({res.status_code}): {res.text}")
            except Exception as e:
                st.error(f"Failed to query backend: {str(e)}")

# -------------------------------------------------------------
# TAB 4: CLOUD INGESTION & S3 MANAGER
# -------------------------------------------------------------
elif app_mode == "☁️ Cloud Ingestion & S3 Manager":
    st.markdown('<div class="main-header">☁️ Cloud Ingestion & S3 Log Portal</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Ingest raw security logs directly into AWS S3 storage buckets for downstream pipeline processing</div>', unsafe_allow_html=True)

    s3_c1, s3_c2 = st.columns(2)
    with s3_c1:
        st.write("##### 🪣 AWS Configuration Status")
        bucket_env = os.environ.get("TDX_S3_BUCKET", "Not Configured")
        region_env = os.environ.get("AWS_REGION", "us-east-1")
        st.write(f"**Target S3 Bucket:** `{bucket_env}`")
        st.write(f"**AWS Region:** `{region_env}`")
        if bucket_env == "Not Configured":
            st.caption("ℹ️ To enable live AWS S3 uploads, set `TDX_S3_BUCKET` in your environment or deploy Terraform IaC.")

    with s3_c2:
        st.write("##### 📤 Upload Log File")
        log_upload = st.file_uploader("Select log file (.json, .csv, .log)", type=["json", "csv", "log", "txt"])
        
        if log_upload is not None:
            if st.button("🚀 Upload to Ingestion Pipeline", type="primary"):
                files = {"file": (log_upload.name, log_upload.getvalue())}
                try:
                    res = requests.post(f"{backend_url}/api/upload", files=files, timeout=15)
                    if res.status_code == 200:
                        st.success("✅ File uploaded successfully!")
                        st.json(res.json())
                    else:
                        st.error(f"Upload failed ({res.status_code}): {res.text}")
                except Exception as e:
                    st.error(f"Upload error: {str(e)}")

# -------------------------------------------------------------
# TAB 5: ARCHITECTURE & MODEL INFO
# -------------------------------------------------------------
elif app_mode == "📖 Architecture & Model Info":
    st.markdown('<div class="main-header">📖 ThreatDetectX Architecture & Model Info</div>', unsafe_allow_html=True)
    
    st.markdown("""
    ### 🏛️ System Architecture
    ThreatDetectX integrates modern cloud and machine learning technologies to deliver an automated threat detection and enrichment pipeline:
    
    1. **Data Ingestion**: Ingests AWS CloudTrail Insight logs and network telemetry into AWS S3.
    2. **AI Detection Engine**: Uses scikit-learn's **Isolation Forest** unsupervised algorithm to isolate anomalous behavioral patterns in connection duration, bytes transferred, and packet counts.
    3. **Threat Intelligence Enrichment**: Flagged anomalies with associated IP indicators are enriched via the **AbuseIPDB** API to assess threat severity.
    4. **SOC Analyst Dashboard**: Streamlit-based web console for real-time inference, batch CSV log scanning, and threat intelligence lookups.
    5. **Infrastructure as Code**: Terraform configurations provisioning encrypted S3 log storage and least-privilege IAM roles.

    ### 🤖 Machine Learning Model: Isolation Forest
    - **Algorithm**: `IsolationForest(n_estimators=100, contamination=0.2, random_state=42)`
    - **Features**: `duration`, `bytes_sent`, `bytes_received`, `packets`
    - **Anomaly Decision Boundary**: Normal traffic produces scores $> 0$, anomalous outliers produce scores $< 0$.
    """)
