"""Application-level encryption for sensitive fields at rest.

Uses Fernet (AES-128-CBC + HMAC). Ciphertext rows carry a versioned sentinel
prefix so keys can be rotated without losing historical data:

- ``enc:v1:`` — legacy derivation from ``SECRET_KEY`` (SHA-256)
- ``enc:v2:`` — dedicated ``DATA_ENCRYPTION_KEY`` (SHA-256), separate from
  the JWT/signing secret

New writes use v2 when ``DATA_ENCRYPTION_KEY`` is configured, and fall back
to the v1 derivation otherwise so a fresh clone with only ``SECRET_KEY``
keeps working. Rotation path: set ``DATA_ENCRYPTION_KEY``; v1 rows remain
readable via ``SECRET_KEY`` and can be re-encrypted in a maintenance window.
Keys live in .env/Vault and never in the database. Decryption failures raise
(fail-loud) instead of returning a placeholder that would silently corrupt
downstream behavior.
"""

import base64
import hashlib
import json
import logging
from typing import Any, Optional

from ..config.settings import settings

logger = logging.getLogger(__name__)

_SENTINEL_V1 = "enc:v1:"
_SENTINEL_V2 = "enc:v2:"
_fernets: dict = {}


class FieldDecryptionError(RuntimeError):
    """A stored ciphertext could not be decrypted with any configured key."""


def _get_fernet(version: str):
    cached = _fernets.get(version)
    if cached is not None:
        return cached
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        logger.warning("cryptography not installed — field encryption disabled, storing plaintext")
        return None

    if version == "v2":
        source = (getattr(settings, "DATA_ENCRYPTION_KEY", "") or "").encode("utf-8")
    else:
        source = (getattr(settings, "SECRET_KEY", "") or "").encode("utf-8")
    derived = base64.urlsafe_b64encode(hashlib.sha256(source).digest())
    fernet = Fernet(derived)
    _fernets[version] = fernet
    return fernet


def encrypt_field(plaintext: Optional[str]) -> str:
    """Encrypt a field if encryption is enabled; returns sentinel-prefixed ciphertext."""
    value = plaintext or ""
    if not getattr(settings, "ENCRYPT_LOGS_AT_REST", False):
        return value
    if (getattr(settings, "DATA_ENCRYPTION_KEY", "") or "").strip():
        version = "v2"
    elif (getattr(settings, "SECRET_KEY", "") or "").strip():
        version = "v1"
    else:
        # No key material at all: storing plaintext honestly beats a
        # deterministic SHA-256(b"") key that provides false confidence.
        logger.warning("ENCRYPT_LOGS_AT_REST is enabled but no encryption key is configured — storing plaintext")
        return value
    fernet = _get_fernet(version)
    if fernet is None:
        return value
    try:
        token = fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return (_SENTINEL_V2 if version == "v2" else _SENTINEL_V1) + token
    except Exception as exc:  # fail-closed to plaintext would leak; raise instead
        logger.error("Field encryption failed: %s", exc)
        raise


def decrypt_field(stored: Optional[str]) -> str:
    """Decrypt a stored field. Plaintext (legacy/unencrypted) passes through.

    Raises FieldDecryptionError when the ciphertext cannot be decrypted with
    the configured key for its version — callers decide how to surface it.
    """
    value = stored or ""
    if value.startswith(_SENTINEL_V2):
        version, sentinel = "v2", _SENTINEL_V2
    elif value.startswith(_SENTINEL_V1):
        version, sentinel = "v1", _SENTINEL_V1
    else:
        return value
    fernet = _get_fernet(version)
    if fernet is None:
        raise FieldDecryptionError(
            f"cryptography not installed: cannot decrypt {version} ciphertext"
        )
    try:
        return fernet.decrypt(value[len(sentinel):].encode("ascii")).decode("utf-8", errors="replace")
    except Exception as exc:
        raise FieldDecryptionError(
            f"Field decryption failed ({version}); check that the matching "
            f"{'DATA_ENCRYPTION_KEY' if version == 'v2' else 'SECRET_KEY'} is configured"
        ) from exc


def encrypt_json(value: Any) -> str:
    return encrypt_field(json.dumps(value, separators=(",", ":")))


def decrypt_json(stored: Optional[str], default: Any) -> Any:
    try:
        return json.loads(decrypt_field(stored))
    except (TypeError, ValueError, FieldDecryptionError):
        return default


def is_encrypted(stored: Optional[str]) -> bool:
    return bool(stored) and (stored.startswith(_SENTINEL_V1) or stored.startswith(_SENTINEL_V2))
