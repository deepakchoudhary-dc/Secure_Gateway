"""Response cache for identical LLM requests within one caller scope.

Key = SHA-256(tenant_id + subject + prompt + system_prompt + retrieved_context + model).
Only successful, unflagged "allowed" responses are cached; anything
blocked/redacted/HITL is never cached. TTL-bounded, size-capped.

ponytail: in-process dict cache — Redis if multi-node cache coherence matters.
"""

import hashlib
import threading
import time
from typing import Dict, Optional, Tuple

from ..config.settings import settings

_cache: Dict[str, Tuple[float, str]] = {}
_lock = threading.Lock()
_MAX_ENTRIES = 512


def _ttl_seconds() -> int:
    return int(getattr(settings, "RESPONSE_CACHE_TTL_SECONDS", 300) or 0)


def cache_key(
    tenant_id: str,
    subject: str,
    prompt: str,
    system_prompt: Optional[str],
    retrieved_context: Optional[str],
    model: Optional[str],
) -> str:
    h = hashlib.sha256()
    for part in (tenant_id, subject, prompt or "", system_prompt or "", retrieved_context or "", model or ""):
        h.update(part.encode("utf-8", errors="replace"))
        h.update(b"\x00")
    return h.hexdigest()


def get(key: str) -> Optional[str]:
    ttl = _ttl_seconds()
    if ttl <= 0:
        return None
    with _lock:
        entry = _cache.get(key)
        if not entry:
            return None
        ts, response = entry
        if time.time() - ts > ttl:
            _cache.pop(key, None)
            return None
        return response


def put(key: str, response: str) -> None:
    ttl = _ttl_seconds()
    if ttl <= 0 or not response:
        return
    with _lock:
        # ponytail: clear-all on overflow instead of LRU bookkeeping — real hit patterns are tiny working sets
        if len(_cache) >= _MAX_ENTRIES:
            cutoff = time.time() - ttl
            for k in [k for k, (ts, _) in _cache.items() if ts < cutoff]:
                _cache.pop(k, None)
            if len(_cache) >= _MAX_ENTRIES:
                _cache.clear()
        _cache[key] = (time.time(), response)


def clear() -> None:
    with _lock:
        _cache.clear()


def stats() -> Dict[str, int]:
    with _lock:
        return {"entries": len(_cache)}
