"""Tests for the IsolationForest inference wrappers."""

import pytest
from detection_engine.anomaly_detector import predict_batch, predict_single

NORMAL = {"duration": 10, "bytes_sent": 1200, "bytes_received": 800, "packets": 32}
EXFIL = {"duration": 5, "bytes_sent": 200000, "bytes_received": 500, "packets": 300}


def test_predict_single_shape():
    result = predict_single(NORMAL)
    assert set(result) == {"prediction", "score", "is_anomaly"}
    assert result["prediction"] in {"normal", "anomalous"}
    assert isinstance(result["is_anomaly"], bool)


def test_predict_single_flags_exfiltration():
    # A massive-upload session should read as anomalous under any sane model.
    assert predict_single(EXFIL)["is_anomaly"] is True


def test_predict_batch_preserves_order_and_count():
    records = [NORMAL, EXFIL, NORMAL]
    results = predict_batch(records)
    assert len(results) == 3
    assert all("anomaly_score" in r for r in results)
    assert results[1]["is_anomaly"] is True


def test_predict_batch_missing_feature_raises():
    with pytest.raises(ValueError):
        predict_batch([{"duration": 1, "bytes_sent": 2}])
