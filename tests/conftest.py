"""Shared pytest fixtures and path setup for the ThreatDetectX test suite."""

import os
import sys

import pytest

# The backend uses flat imports (e.g. `from services.threat_intel import ...`),
# so the `backend/` directory must be importable as a source root.
BACKEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)


@pytest.fixture()
def client():
    """Flask test client with the AbuseIPDB key unset (offline mode)."""
    os.environ.pop("ABUSEIPDB_KEY", None)
    os.environ.pop("TDX_S3_BUCKET", None)
    from app import app

    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c
