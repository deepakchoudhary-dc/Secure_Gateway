"""
Tests for production boot-time validation gates added/verified in audit.md remediation.
Each test builds a fully valid production Settings, then flips ONE field to prove its gate fires.
"""

import os
import pytest

from src.config.settings import Settings


VALID = {
    "ENVIRONMENT": "production",
    "SECRET_KEY": "p" * 64,
    "AUTH_MODE": "jwt",
    "JWT_SECRET_KEY": "j" * 64,
    # Pinned because conftest exports REQUIRE_AUTH=false for the API test suite
    "REQUIRE_AUTH": True,
    "REQUIRE_ADMIN_AUTH": True,
    # Pinned because .env sets this true for development
    "REDTEAM_ENDPOINTS_ENABLED": False,
    "DATABASE_URL": "postgresql://user:pass@db.internal:5432/ai_security",
    "PROVIDER_EGRESS_ALLOWLIST": "api.openai.com,api.anthropic.com",
    "SECRETS_BACKEND": "vault",
    "VAULT_ADDR": "https://vault.example.com",
    "ALLOWED_ORIGINS": "https://app.example.com",
    "HITL_EMAIL": "security-team@example.com",
}


@pytest.fixture
def prod_env(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    return VALID


def make_settings(**overrides):
    values = dict(VALID)
    values.update(overrides)
    return Settings(**values)


def test_valid_production_config_boots(prod_env):
    s = make_settings()
    assert s._is_production
    assert s.ALLOWED_ORIGINS == ["https://app.example.com"]


def test_sqlite_rejected_in_production(prod_env):
    with pytest.raises(ValueError, match="client-server"):
        make_settings(DATABASE_URL="sqlite:///./prod.db")


def test_placeholder_hitl_email_rejected(prod_env):
    with pytest.raises(ValueError, match="HITL_EMAIL"):
        make_settings(HITL_EMAIL="admin@example.com")


def test_http_origin_rejected_in_production(prod_env):
    # _validated_origins is now wired into boot; insecure non-localhost origins must fail
    with pytest.raises(ValueError, match="HTTPS"):
        make_settings(ALLOWED_ORIGINS="http://app.example.com")


def test_wildcard_origin_with_credentials_rejected(prod_env):
    with pytest.raises(ValueError):
        make_settings(ALLOWED_ORIGINS="*")


def test_missing_egress_allowlist_rejected(prod_env):
    with pytest.raises(ValueError, match="EGRESS_ALLOWLIST"):
        make_settings(PROVIDER_EGRESS_ALLOWLIST="")


def test_http_outbound_model_url_rejected(prod_env):
    from src.gateway.router import _validate_outbound_url
    with pytest.raises(ValueError, match="HTTPS"):
        _validate_outbound_url("http://api.openai.com/v1")
    with pytest.raises(ValueError, match="non-public|resolve|HTTPS"):
        _validate_outbound_url("https://127.0.0.1/v1")


def test_ai_request_still_accepts_context_field():
    """Regression guard: context was briefly deleted; the HITL dashboard renders it."""
    from src.gateway.router import AIRequest
    req = AIRequest(prompt="hi", context="Simulation Payload ID: x")
    assert req.context == "Simulation Payload ID: x"
