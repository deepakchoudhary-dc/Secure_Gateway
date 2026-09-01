"""Response cache for identical LLM requests within one caller scope.

Key = SHA-256(tenant_id + subject + prompt + system_prompt + retrieved_context + model).
Only successful, unflagged "allowed" responses are cached; anything
blocked/redacted/HITL is never cached. TTL-bounded, size-capped.

For small teams, the in-process cache is sufficient. For larger deployments,
consider Redis for distributed cache coherence.
"""

import hashlib
import logging
import threading
import time
from typing import Dict, Optional, Tuple

from ..config.settings import settings

logger = logging.getLogger(__name__)

_cache: Dict[str, Tuple[float, str]] = {}
_lock = threading.Lock()
_MAX_ENTRIES = 512
_stats = {"hits": 0, "misses": 0, "evictions": 0}


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
            _stats["misses"] += 1
            return None
        ts, response = entry
        if time.time() - ts > ttl:
            _cache.pop(key, None)
            _stats["misses"] += 1
            return None
        _stats["hits"] += 1
        return response


def put(key: str, response: str) -> None:
    ttl = _ttl_seconds()
    if ttl <= 0 or not response:
        return
    with _lock:
        evicted = 0
        if len(_cache) >= _MAX_ENTRIES:
            cutoff = time.time() - ttl
            expired_keys = [k for k, (ts, _) in _cache.items() if ts < cutoff]
            for k in expired_keys:
                _cache.pop(k, None)
                evicted += 1
            if len(_cache) >= _MAX_ENTRIES:
                _cache.clear()
                evicted = len(_cache)
        _cache[key] = (time.time(), response)
        if evicted > 0:
            _stats["evictions"] += evicted
            logger.debug("Cache evicted %d entries", evicted)


def clear() -> None:
    with _lock:
        cleared = len(_cache)
        _cache.clear()
        logger.info("Cache cleared: %d entries", cleared)


def stats() -> Dict[str, int]:
    with _lock:
        total_requests = _stats["hits"] + _stats["misses"]
        hit_rate = _stats["hits"] / total_requests if total_requests > 0 else 0.0
        return {
            "entries": len(_cache),
            "hits": _stats["hits"],
            "misses": _stats["misses"],
            "evictions": _stats["evictions"],
            "hit_rate": round(hit_rate, 3),
        }


def reset_stats() -> None:
    with _lock:
        _stats["hits"] = 0
        _stats["misses"] = 0
        _stats["evictions"] = 0
