"""Integration tests for the Flask REST API using the test client."""


def test_health_endpoint(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "healthy"
    assert "/api/detect" in body["endpoints"]


def test_detect_missing_fields_returns_400(client):
    resp = client.post("/api/detect", json={"duration": 10})
    assert resp.status_code == 400
    assert "Missing keys" in resp.get_json()["error"]


def test_detect_valid_record(client):
    resp = client.post("/api/detect", json={
        "duration": 10, "bytes_sent": 1200, "bytes_received": 800, "packets": 32,
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["prediction"] in {"normal", "anomalous"}
    assert "score" in body


def test_detect_with_ip_enriches(client):
    resp = client.post("/api/detect", json={
        "duration": 5, "bytes_sent": 200000, "bytes_received": 500,
        "packets": 300, "ip": "185.220.101.5",
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["threat_level"] == "CRITICAL"


def test_detect_batch(client):
    resp = client.post("/api/detect_batch", json={"records": [
        {"duration": 10, "bytes_sent": 1200, "bytes_received": 800, "packets": 32},
        {"duration": 5, "bytes_sent": 200000, "bytes_received": 500, "packets": 300},
    ]})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total_records"] == 2
    assert body["anomaly_count"] >= 1


def test_check_ip_endpoint(client):
    resp = client.post("/api/check_ip", json={"ip": "8.8.8.8"})
    assert resp.status_code == 200
    assert resp.get_json()["threat_level"] == "CLEAN"


def test_check_ip_missing_field(client):
    resp = client.post("/api/check_ip", json={})
    assert resp.status_code == 400
