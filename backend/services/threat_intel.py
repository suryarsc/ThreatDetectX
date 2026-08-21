import os

import requests
from dotenv import load_dotenv

load_dotenv()

def get_abuseipdb_key():
    return os.environ.get("ABUSEIPDB_KEY")

def evaluate_threat_level(score):
    """Categorize abuse score (0-100) into severity levels."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "CLEAN"

def check_ip_reputation(ip):
    """
    Check IP reputation with AbuseIPDB.
    Returns structured threat intelligence info.
    If no API key is provided, returns simulated threat intel for demo/offline development.
    """
    ip = str(ip).strip()
    api_key = get_abuseipdb_key()

    if not api_key or api_key.strip() == "":
        # Local evaluation mode when external API key is not configured
        is_suspicious = ip.startswith("185.") or ip.startswith("194.") or ip.endswith(".100")
        score = 85 if is_suspicious else 0
        return {
            "ip": ip,
            "abuse_confidence_score": score,
            "threat_level": evaluate_threat_level(score),
            "isp": "Known Hosting/Transit Provider" if is_suspicious else "Cloud Infrastructure",
            "country_code": "RU" if is_suspicious else "US",
            "usage_type": "Data Center/Web Hosting/Transit",
            "total_reports": 42 if is_suspicious else 0,
            "last_reported_at": "2026-08-20T12:00:00+00:00" if is_suspicious else None,
            "is_whitelisted": not is_suspicious,
            "offline_mode": True,
            "status_message": (
                "Local baseline evaluation active "
                "(set ABUSEIPDB_KEY in .env for live API queries)."
            ),
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)

        return {
            "ip": ip,
            "abuse_confidence_score": score,
            "threat_level": evaluate_threat_level(score),
            "isp": data.get("isp", "Unknown"),
            "country_code": data.get("countryCode", "Unknown"),
            "country_name": data.get("countryName", "Unknown"),
            "domain": data.get("domain", "Unknown"),
            "usage_type": data.get("usageType", "Unknown"),
            "total_reports": data.get("totalReports", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "is_whitelisted": data.get("isWhitelisted", False),
            "simulated": False,
            "raw": data
        }
    except Exception as e:
        return {
            "ip": ip,
            "error": str(e),
            "threat_level": "UNKNOWN",
            "abuse_confidence_score": 0,
            "simulated": False
        }
