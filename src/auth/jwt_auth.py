"""
JWT token issuance and verification for the AI Security Gateway.

Supports HS256 (symmetric) and RS256 (asymmetric) algorithms.
Tokens carry subject, tenant_id, roles, and standard JWT claims.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt as pyjwt

from ..config.settings import settings

logger = logging.getLogger(__name__)

_SUPPORTED_ALGORITHMS = {"HS256", "RS256"}
_MAX_TOKEN_LENGTH = 8192

def revoke_jti(jti: str, expires_at: datetime) -> None:
    """Persist a token revocation so every application replica enforces it."""
    from ..monitoring.database import RevokedToken, SessionLocal

    session = SessionLocal()
    try:
        if not session.query(RevokedToken.id).filter(RevokedToken.jti == jti).first():
            session.add(RevokedToken(jti=jti, expires_at=expires_at))
            session.commit()
    except Exception as exc:
        session.rollback()
        raise TokenError("Token revocation could not be persisted") from exc
    finally:
        session.close()


def is_jti_revoked(jti: str) -> bool:
    """Fail closed when revocation state cannot be checked."""
    from ..monitoring.database import RevokedToken, SessionLocal

    session = SessionLocal()
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        return session.query(RevokedToken.id).filter(
            RevokedToken.jti == jti,
            RevokedToken.expires_at > now,
        ).first() is not None
    except Exception as exc:
        logger.error("Token revocation lookup failed: %s", exc)
        return True
    finally:
        session.close()

class TokenError(Exception):
    """Raised when a token cannot be created or verified."""


def _resolve_algorithm() -> str:
    alg = getattr(settings, "JWT_ALGORITHM", "HS256")
    if alg not in _SUPPORTED_ALGORITHMS:
        raise TokenError(f"Unsupported JWT algorithm: {alg}")
    return alg


def _resolve_signing_key() -> str:
    key = getattr(settings, "JWT_SECRET_KEY", "") or settings.SECRET_KEY
    if not key:
        raise TokenError("JWT signing key is not configured")
    return key


def _resolve_verification_key() -> str:
    """For RS256 the verification key may differ (public key).  Falls back to signing key for HS256."""
    return getattr(settings, "JWT_PUBLIC_KEY", "") or _resolve_signing_key()


def create_access_token(
    subject: str,
    tenant_id: str,
    roles: List[str],
    extra_claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Issue a signed JWT with standard and gateway-specific claims."""
    algorithm = _resolve_algorithm()
    key = _resolve_signing_key()

    now = datetime.now(timezone.utc)
    expiry = expires_delta or timedelta(minutes=getattr(settings, "JWT_EXPIRY_MINUTES", 30))
    exp = now + expiry

    payload: Dict[str, Any] = {
        "sub": subject,
        "tenant_id": tenant_id,
        "roles": roles,
        "iat": now,
        "exp": exp,
        "iss": getattr(settings, "JWT_ISSUER", "ai-security-gateway"),
        "jti": uuid.uuid4().hex,
    }
    audience = getattr(settings, "JWT_AUDIENCE", "")
    if audience:
        payload["aud"] = audience
    if extra_claims:
        payload.update(extra_claims)

    try:
        token: str = pyjwt.encode(payload, key, algorithm=algorithm)
        return token
    except Exception as exc:
        logger.error("Failed to create JWT: %s", exc)
        raise TokenError("Token creation failed") from exc


def decode_access_token(token: str) -> Dict[str, Any]:
    """Verify and decode a JWT.  Returns the full claims dict on success."""
    if not isinstance(token, str) or len(token) > _MAX_TOKEN_LENGTH:
        raise TokenError("Invalid token")
    algorithm = _resolve_algorithm()
    key = _resolve_verification_key()

    decode_options: Dict[str, Any] = {
        "algorithms": [algorithm],
        "options": {"require": ["sub", "tenant_id", "roles", "exp", "iat"]},
    }

    issuer = getattr(settings, "JWT_ISSUER", "ai-security-gateway")
    if issuer:
        decode_options["issuer"] = issuer

    audience = getattr(settings, "JWT_AUDIENCE", "")
    if audience:
        decode_options["audience"] = audience

    try:
        claims: Dict[str, Any] = pyjwt.decode(token, key, **decode_options)
        jti = claims.get("jti")
        if jti and is_jti_revoked(jti):
            raise TokenError("Token has been revoked")
        return claims
    except pyjwt.ExpiredSignatureError as exc:
        raise TokenError("Token has expired") from exc
    except pyjwt.InvalidTokenError as exc:
        raise TokenError(f"Invalid token: {exc}") from exc
