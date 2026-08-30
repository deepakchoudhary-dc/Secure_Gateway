"""Application-level encryption for sensitive fields at rest.

Uses Fernet (AES-128-CBC + HMAC) keyed from SECRET_KEY via SHA-256, so the
key lives in .env/vault and never in the database. Ciphertext rows carry an
``enc:v1:`` sentinel prefix so legacy plaintext rows remain readable and
migration is seamless.
"""

import base64
import hashlib
import json
import logging
from typing import Any, Optional

from ..config.settings import settings

logger = logging.getLogger(__name__)

_SENTINEL = "enc:v1:"
_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is None:
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            logger.warning("cryptography not installed — field encryption disabled, storing plaintext")
            return None

        key = (getattr(settings, "SECRET_KEY", "") or "").encode("utf-8")
        derived = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
        _fernet = Fernet(derived)
    return _fernet


def encrypt_field(plaintext: Optional[str]) -> str:
    """Encrypt a field if encryption is enabled; returns sentinel-prefixed ciphertext."""
    value = plaintext or ""
    if not getattr(settings, "ENCRYPT_LOGS_AT_REST", False):
        return value
    fernet = _get_fernet()
    if fernet is None:
        return value
    try:
        token = fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return _SENTINEL + token
    except Exception as exc:  # fail-closed to plaintext would leak; raise instead
        logger.error("Field encryption failed: %s", exc)
        raise


def decrypt_field(stored: Optional[str]) -> str:
    """Decrypt a stored field. Plaintext (legacy/unencrypted) passes through."""
    value = stored or ""
    if not value.startswith(_SENTINEL):
        return value
    fernet = _get_fernet()
    if fernet is None:
        return value[len(_SENTINEL):]
    try:
        return fernet.decrypt(value[len(_SENTINEL):].encode("ascii")).decode("utf-8", errors="replace")
    except Exception as exc:
        logger.error("Field decryption failed: %s", exc)
        return "[DECRYPTION ERROR]"


def encrypt_json(value: Any) -> str:
    return encrypt_field(json.dumps(value, separators=(",", ":")))


def decrypt_json(stored: Optional[str], default: Any) -> Any:
    try:
        return json.loads(decrypt_field(stored))
    except (TypeError, ValueError):
        return default


def is_encrypted(stored: Optional[str]) -> bool:
    return bool(stored) and stored.startswith(_SENTINEL)
