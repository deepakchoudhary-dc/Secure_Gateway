"""
Tests for the inbound sensitive-data gate (DLP-lite):
credential material and bulk PII are blocked before reaching the LLM,
and the blocked payload is never persisted to the audit log.
"""

import os
os.environ.setdefault("DATABASE_URL", f"sqlite:///{os.path.join(os.environ.get('TEMP', '.'), 'ai_security_test.db')}")
os.environ.setdefault("LOG_FORMAT", "text")

from src.monitoring.database import init_db
init_db()

import pytest

from src.auth.tenant import CurrentUser
from src.filters.input_filter import InputFilter
from src.gateway.router import AIRequest, process_ai_request_impl
from src.monitoring.database import SessionLocal, SecurityLog
from src.policy.policy_manager import PolicyManager


USER = CurrentUser(subject="dlp_user", tenant_id="default", roles=["user"])

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def _last_log_prompt():
    session = SessionLocal()
    try:
        row = (
            session.query(SecurityLog)
            .filter(SecurityLog.user_id == "dlp_user")
            .order_by(SecurityLog.id.desc())
            .first()
        )
        return row.prompt if row else None
    finally:
        session.close()


class TestSensitiveDataGate:
    @pytest.mark.asyncio
    async def test_credential_in_prompt_blocked(self):
        req = AIRequest(prompt=f"please summarize this deploy note key={AWS_KEY}")
        resp = await process_ai_request_impl(req, current_user=USER)
        assert resp.action_taken == "blocked_sensitive_data"
        assert any(a["type"] == "sensitive_data_violation" for a in resp.anomalies)

    @pytest.mark.asyncio
    async def test_credential_in_retrieved_context_blocked(self):
        req = AIRequest(
            prompt="what does this config do?",
            retrieved_context=f"settings:\n  token: {GH_TOKEN}\n  env: prod",
        )
        resp = await process_ai_request_impl(req, current_user=USER)
        assert resp.action_taken == "blocked_sensitive_data"

    @pytest.mark.asyncio
    async def test_bulk_pii_blocked(self):
        emails = " ".join(f"user{i}@corp.example.com" for i in range(10))
        req = AIRequest(prompt=f"customer contact list: {emails}")
        resp = await process_ai_request_impl(req, current_user=USER)
        assert resp.action_taken == "blocked_sensitive_data"

    @pytest.mark.asyncio
    async def test_normal_prompt_passes_gate(self):
        resp = await process_ai_request_impl(AIRequest(prompt="hello there friend"), current_user=USER)
        # May fail later at the provider in test envs — the gate itself must pass.
        assert resp.action_taken != "blocked_sensitive_data"

    @pytest.mark.asyncio
    async def test_blocked_payload_never_persisted(self):
        secret = f"key={AWS_KEY} token={GH_TOKEN}"
        await process_ai_request_impl(AIRequest(prompt=f"upload notes: {secret}"), current_user=USER)
        logged = _last_log_prompt()
        assert logged is not None
        assert AWS_KEY not in logged and GH_TOKEN not in logged
        assert logged.startswith("[REDACTED")

    @pytest.mark.asyncio
    async def test_policy_can_disable_gate(self):
        pm = PolicyManager()
        original = pm.get_policies()
        try:
            policies = pm.get_policies()
            policies["input_validation"]["rules"]["sensitive_data"]["enabled"] = False
            pm.update_policies(policies)

            resp = await process_ai_request_impl(
                AIRequest(prompt=f"notes with {AWS_KEY}"), current_user=USER
            )
            assert resp.action_taken != "blocked_sensitive_data"
        finally:
            pm.update_policies(original)


class TestScanUnit:
    def test_findings_count_per_kind(self):
        f = InputFilter().scan_sensitive_data(
            f"mail me at bob@x.com or alice@y.com, card 4111 1111 1111 1111"
        )
        assert f.get("Email") == 2
        assert f.get("Credit Card") >= 1

    def test_ssn_detected(self):
        f = InputFilter().scan_sensitive_data("employee ssn 123-45-6789")
        assert f.get("US SSN") == 1
