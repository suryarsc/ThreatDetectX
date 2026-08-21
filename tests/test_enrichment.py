"""Tests for record enrichment with threat intelligence."""

from enrichment.enrichment import enrich_record, enrich_threats


def test_enrich_record_with_suspicious_ip(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)
    record = {"src_ip": "185.220.101.5", "is_anomaly": True}
    out = enrich_record(record)
    assert out["threat_level"] == "CRITICAL"
    assert out["abuse_score"] == 85
    assert out["threat_intel"] is not None


def test_enrich_record_without_ip_defaults_by_anomaly():
    anomalous = enrich_record({"is_anomaly": True})
    clean = enrich_record({"is_anomaly": False})
    assert anomalous["threat_level"] == "SUSPICIOUS"
    assert anomalous["threat_intel"] is None
    assert clean["threat_level"] == "CLEAN"


def test_enrich_record_ignores_nan_ip():
    out = enrich_record({"src_ip": "nan", "is_anomaly": False})
    assert out["threat_level"] == "CLEAN"


def test_enrich_threats_batch(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)
    records = [{"ip": "8.8.8.8"}, {"ip": "185.10.10.10"}]
    enriched = enrich_threats(records)
    assert len(enriched) == 2
    assert enriched[0]["threat_level"] == "CLEAN"
    assert enriched[1]["threat_level"] == "CRITICAL"
