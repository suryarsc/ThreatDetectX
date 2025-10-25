import os
import requests

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY")  # set this locally for testing

def check_ip_reputation(ip):
    if not ABUSEIPDB_KEY:
        return {"error": "ABUSEIPDB_KEY not configured", "ip": ip}

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_KEY
    }
    r = requests.get(url, headers=headers, params=params, timeout=10)
    try:
        r.raise_for_status()
    except Exception as e:
        return {"error": str(e), "status_code": r.status_code, "text": r.text}
    return r.json()
