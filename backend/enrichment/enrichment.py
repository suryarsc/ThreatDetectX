def enrich_threats(anomalies):
    # Placeholder for threat intelligence enrichment
    for a in anomalies:
        a["threat_level"] = "unknown"  # will integrate AbuseIPDB/VirusTotal later
    return anomalies

if __name__ == "__main__":
    from backend.detection_engine.detection_engine import detect_anomalies
    from backend.data_ingestion.data_ingestion import load_logs

    logs = load_logs()
    anomalies = detect_anomalies(logs)
    enriched = enrich_threats(anomalies)
    print(enriched)
