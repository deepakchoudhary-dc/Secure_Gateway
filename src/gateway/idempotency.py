"""Durable, tenant-scoped idempotency control for side-effecting gateway requests.

The service intentionally commits a claim before application side effects.  It
never automatically replays a stale in-progress request: after a process crash
its external outcome is unknowable, and retrying could duplicate a paid or
state-changing provider operation.
"""

import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Mapping, Optional

from sqlalchemy.exc import IntegrityError

from ..config.settings import settings
from ..monitoring.database import IdempotencyRecord, SessionLocal

_KEY_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{16,128}$")
_FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ENDPOINT = "/api/v1/process"
_IN_PROGRESS = "in_progress"
_COMPLETED = "completed"


class IdempotencyError(Exception):
    """Base exception for a request that cannot safely be processed."""

    status_code = 409


class IdempotencyConflict(IdempotencyError):
    """The key was reused with a request that is materially different."""


class IdempotencyInProgress(IdempotencyError):
    """The original request is active or its terminal outcome is unknown."""


@dataclass(frozen=True)
class IdempotencyClaim:
    """Opaque ownership token returned only to the request that created it."""

    record_id: int
    execution_token: str


class IdempotencyService:
    """Portable database-backed idempotency claim and replay service.

    ``claim_or_replay`` has exactly three safe outcomes:

    * a new :class:`IdempotencyClaim` owned by the caller;
    * a validated completed response to replay; or
    * an idempotency exception that must be returned without side effects.
    """

    def validate_key(self, key: Optional[str]) -> str:
        if not isinstance(key, str) or not _KEY_PATTERN.fullmatch(key):
            raise ValueError("Idempotency-Key must be 16-128 URL-safe characters")
        return key

    def fingerprint(self, body: Mapping[str, Any]) -> str:
        """Return a canonical SHA-256 request fingerprint without persisting input."""
        if not isinstance(body, Mapping):
            raise ValueError("Idempotency request body must be a mapping")
        try:
            canonical = json.dumps(
                dict(body),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("Idempotency request body is not canonical JSON") from exc
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def claim_or_replay(
        self, *, tenant_id: str, subject: str, key: str, request_fingerprint: str
    ) -> tuple[Optional[IdempotencyClaim], Optional[Dict[str, Any]]]:
        self._validate_scope(tenant_id, subject)
        self.validate_key(key)
        self._validate_fingerprint(request_fingerprint)
        key_digest = self._key_digest(key)
        now = datetime.utcnow()
        session = SessionLocal()
        try:
            existing = self._get(session, tenant_id, subject, key_digest)
            if existing is not None:
                if self._is_expired(existing, now):
                    session.delete(existing)
                    session.commit()
                else:
                    return self._existing(existing, request_fingerprint)

            token = uuid.uuid4().hex
            record = IdempotencyRecord(
                tenant_id=tenant_id,
                subject=subject,
                endpoint=_ENDPOINT,
                key_digest=key_digest,
                request_fingerprint=request_fingerprint,
                state=_IN_PROGRESS,
                execution_token=token,
                created_at=now,
                updated_at=now,
                expires_at=now + timedelta(seconds=self._ttl_seconds()),
            )
            session.add(record)
            try:
                session.commit()
                return IdempotencyClaim(record.id, token), None
            except IntegrityError:
                # The unique database constraint is the concurrency control.  The
                # winner is read only after rollback so no partial session state
                # leaks into the replay decision.
                session.rollback()
                winner = self._get(session, tenant_id, subject, key_digest)
                if winner is None:
                    raise IdempotencyInProgress("Concurrent idempotency claim could not be resolved")
                return self._existing(winner, request_fingerprint)
        finally:
            session.close()

    def complete(
        self,
        claim: IdempotencyClaim,
        response: Mapping[str, Any],
        *,
        status_code: int = 200,
    ) -> None:
        """Atomically store a replayable terminal response for the claim owner."""
        if not isinstance(claim, IdempotencyClaim):
            raise ValueError("A valid idempotency claim is required")
        if not isinstance(status_code, int) or not 200 <= status_code < 400:
            raise ValueError("Only successful HTTP responses may be cached")
        serialized = self._serialize_response(response)

        session = SessionLocal()
        try:
            record = session.query(IdempotencyRecord).filter(
                IdempotencyRecord.id == claim.record_id,
                IdempotencyRecord.execution_token == claim.execution_token,
                IdempotencyRecord.state == _IN_PROGRESS,
            ).first()
            if record is None:
                raise IdempotencyInProgress("Idempotency claim is no longer owned by this request")

            completed_at = datetime.utcnow()
            record.state = _COMPLETED
            record.response_status = status_code
            record.response_json = serialized
            record.completed_at = completed_at
            record.updated_at = completed_at
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def release(self, claim: Optional[IdempotencyClaim]) -> None:
        """Release only failures proven to have occurred before side effects.

        Callers must not invoke this after dispatching a provider request, creating
        a HITL review, or otherwise causing an externally observable action.
        """
        if claim is None:
            return
        if not isinstance(claim, IdempotencyClaim):
            raise ValueError("Invalid idempotency claim")
        session = SessionLocal()
        try:
            session.query(IdempotencyRecord).filter(
                IdempotencyRecord.id == claim.record_id,
                IdempotencyRecord.execution_token == claim.execution_token,
                IdempotencyRecord.state == _IN_PROGRESS,
            ).delete(synchronize_session=False)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @staticmethod
    def _get(session: Any, tenant_id: str, subject: str, key_digest: str) -> Optional[IdempotencyRecord]:
        return session.query(IdempotencyRecord).filter(
            IdempotencyRecord.tenant_id == tenant_id,
            IdempotencyRecord.subject == subject,
            IdempotencyRecord.endpoint == _ENDPOINT,
            IdempotencyRecord.key_digest == key_digest,
        ).first()

    @staticmethod
    def _key_digest(key: str) -> str:
        # The raw client key is never persisted or logged.  A digest is sufficient
        # for equality lookup because keys are high-entropy opaque client values.
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_scope(tenant_id: str, subject: str) -> None:
        if not isinstance(tenant_id, str) or not tenant_id or len(tenant_id) > 100:
            raise ValueError("tenant_id must be a non-empty value of at most 100 characters")
        if not isinstance(subject, str) or not subject or len(subject) > 200:
            raise ValueError("subject must be a non-empty value of at most 200 characters")

    @staticmethod
    def _validate_fingerprint(request_fingerprint: str) -> None:
        if not isinstance(request_fingerprint, str) or not _FINGERPRINT_PATTERN.fullmatch(request_fingerprint):
            raise ValueError("request_fingerprint must be a lowercase SHA-256 hex digest")

    @staticmethod
    def _is_expired(record: IdempotencyRecord, now: datetime) -> bool:
        return bool(record.expires_at and record.expires_at <= now)

    @staticmethod
    def _existing(
        record: IdempotencyRecord, request_fingerprint: str
    ) -> tuple[Optional[IdempotencyClaim], Optional[Dict[str, Any]]]:
        if not hmac.compare_digest(record.request_fingerprint, request_fingerprint):
            raise IdempotencyConflict("Idempotency-Key was already used with a different request")
        if record.state != _COMPLETED:
            raise IdempotencyInProgress("A request with this Idempotency-Key is still in progress or has an unknown outcome")
        if not record.response_json:
            raise IdempotencyError("Completed idempotency record has no replayable response")
        try:
            response = json.loads(record.response_json)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IdempotencyError("Completed idempotency record contains invalid response data") from exc
        if not isinstance(response, dict):
            raise IdempotencyError("Completed idempotency record contains an invalid response shape")
        return None, response

    @staticmethod
    def _ttl_seconds() -> int:
        ttl = getattr(settings, "IDEMPOTENCY_TTL_SECONDS", 86_400)
        if not isinstance(ttl, int) or not 60 <= ttl <= 604_800:
            raise ValueError("IDEMPOTENCY_TTL_SECONDS must be between 60 and 604800")
        return ttl

    @staticmethod
    def _serialize_response(response: Mapping[str, Any]) -> str:
        if not isinstance(response, Mapping):
            raise ValueError("Idempotency response must be a mapping")
        try:
            serialized = json.dumps(
                dict(response), separators=(",", ":"), ensure_ascii=False, allow_nan=False
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("Idempotency response is not valid JSON") from exc
        limit = getattr(settings, "IDEMPOTENCY_MAX_RESPONSE_BYTES", 131_072)
        if not isinstance(limit, int) or limit < 1024:
            raise ValueError("IDEMPOTENCY_MAX_RESPONSE_BYTES must be at least 1024")
        if len(serialized.encode("utf-8")) > limit:
            raise IdempotencyError("Idempotency response exceeds the configured storage limit")
        return serialized