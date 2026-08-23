"""
Tests for B10 fix: API-key mode quota buckets.

Every API-key caller used to share the subject "api_key_user" (one shared
quota bucket). Identity is now per-credential (hashed) and optionally
per-client via X-Client-ID.
"""

import hashlib
import os
os.environ.setdefault("DATABASE_URL", f"sqlite:///{os.path.join(os.environ.get('TEMP', '.'), 'ai_security_test.db')}")
os.environ.setdefault("LOG_FORMAT", "text")

from src.monitoring.database import init_db
init_db()

import pytest

from src.config.settings import settings
from src.monitoring.database import SecurityLog, SessionLocal


@pytest.fixture
def require_auth(client, monkeypatch):
    """Enable auth for these tests; conftest disables it globally."""
    monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
    return {"X-API-Key": settings.API_KEY}


def _latest_subject_for(fragment):
    session = SessionLocal()
    try:
        row = (
            session.query(SecurityLog)
            .filter(SecurityLog.user_id.like(f"%{fragment}%"))
            .order_by(SecurityLog.id.desc())
            .first()
        )
        return row.user_id if row else None
    finally:
        session.close()


class TestApiKeyIdentityBuckets:
    def test_shared_key_without_client_id_gets_credential_bucket(self, client, require_auth):
        resp = client.post("/api/v1/process", json={"prompt": "hello there friend"}, headers=require_auth)
        assert resp.status_code == 200

        expected = f"apikey:{hashlib.sha256(settings.API_KEY.encode()).hexdigest()[:12]}"
        assert _latest_subject_for(expected[:16]) == expected

    def test_client_ids_get_distinct_buckets(self, client, require_auth):
        for cid in ("client-a", "client-b"):
            r = client.post(
                "/api/v1/process",
                json={"prompt": "hello there friend"},
                headers={**require_auth, "X-Client-ID": cid},
            )
            assert r.status_code == 200

        a = _latest_subject_for("apikey:client-a")
        b = _latest_subject_for("apikey:client-b")
        assert a == "apikey:client-a"
        assert b == "apikey:client-b"
        assert a != b  # distinct quota buckets

    def test_invalid_client_id_rejected(self, client, require_auth):
        r = client.post(
            "/api/v1/process",
            json={"prompt": "hello there friend"},
            headers={**require_auth, "X-Client-ID": "bad id with spaces!"},
        )
        assert r.status_code == 400
        assert "X-Client-ID" in r.json()["detail"]

    def test_wrong_still_key_unauthorized(self, client, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        r = client.post(
            "/api/v1/process",
            json={"prompt": "hello there friend"},
            headers={"X-API-Key": "wrong-key-entirely-123456"},
        )
        assert r.status_code == 401
