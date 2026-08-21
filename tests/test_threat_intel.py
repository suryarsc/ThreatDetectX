"""Unit tests for the threat-intelligence scoring and offline evaluation."""

import pytest
from services.threat_intel import check_ip_reputation, evaluate_threat_level


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, "CLEAN"),
        (1, "LOW"),
        (19, "LOW"),
        (20, "MEDIUM"),
        (49, "MEDIUM"),
        (50, "HIGH"),
        (79, "HIGH"),
        (80, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_evaluate_threat_level_boundaries(score, expected):
    assert evaluate_threat_level(score) == expected


def test_offline_mode_flags_suspicious_prefix(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)
    result = check_ip_reputation("185.220.101.5")
    assert result["offline_mode"] is True
    assert result["abuse_confidence_score"] == 85
    assert result["threat_level"] == "CRITICAL"


def test_offline_mode_marks_clean_ip(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)
    result = check_ip_reputation("8.8.8.8")
    assert result["abuse_confidence_score"] == 0
    assert result["threat_level"] == "CLEAN"
    assert result["is_whitelisted"] is True
