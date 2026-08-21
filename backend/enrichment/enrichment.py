from dotenv import load_dotenv
from services.threat_intel import check_ip_reputation

load_dotenv()

def enrich_record(record):
    """
    Enrich a single anomaly/security record with threat intelligence if an IP is detected.
    """
    # Look for common IP address keys
    ip_keys = ["ip", "src_ip", "dst_ip", "source_ip", "destination_ip", "sourceIPAddress"]
    target_ip = None
    for k in ip_keys:
        if k in record and record[k]:
            target_ip = record[k]
            break

    is_valid_ip = (
        isinstance(target_ip, str)
        and target_ip.strip()
        and target_ip.strip().lower() != "nan"
    )
    if is_valid_ip:
        intel = check_ip_reputation(target_ip.strip())
        record["threat_intel"] = intel
        record["threat_level"] = intel.get("threat_level", "CLEAN")
        record["abuse_score"] = intel.get("abuse_confidence_score", 0)
    else:
        # If no IP is in the record, default based on anomaly status
        is_anomaly = record.get("is_anomaly") or record.get("prediction") == "anomalous"
        record["threat_level"] = "SUSPICIOUS" if is_anomaly else "CLEAN"
        record["threat_intel"] = None

    return record

def enrich_threats(anomalies):
    """
    Enrich a batch of anomaly records.
    """
    if isinstance(anomalies, dict):
        return enrich_record(anomalies)

    enriched = []
    for item in anomalies:
        enriched.append(enrich_record(dict(item)))
    return enriched

if __name__ == "__main__":
    sample_anomaly = {
        "duration": 12,
        "bytes_sent": 3400,
        "bytes_received": 1200,
        "packets": 45,
        "src_ip": "185.220.101.5",
        "prediction": "anomalous",
        "is_anomaly": True
    }
    result = enrich_record(sample_anomaly)
    print("Enrichment sample result:", result)
