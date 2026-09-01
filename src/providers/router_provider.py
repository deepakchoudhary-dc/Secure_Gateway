"""
Provider routing with failover, circuit breaker, retry, and egress allowlist.

The ``ProviderRouter`` is the single entry point that the gateway router
uses to send requests to external LLM providers.  It encapsulates:

- Provider selection (primary → fallback)
- Circuit-breaker integration
- Retry with backoff
- Egress domain allowlist enforcement
"""

import ipaddress
import logging
import socket
import time
from typing import Dict, List
from urllib.parse import urlparse

from ..config.settings import settings
from .base import LLMMessage, LLMProvider, LLMResponse, ProviderError
from .circuit_breaker import CircuitBreaker, CircuitBreakerOpen
from .mock_provider import MockProvider
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .gemini_provider import GeminiProvider
from .retry import RetryBudgetExhausted, retry_with_backoff
from .health_monitor import get_health_monitor

logger = logging.getLogger(__name__)


class EgressDenied(ProviderError):
    """Raised when an outbound URL is not on the egress allowlist."""

    def __init__(self, url: str):
        super().__init__(f"Egress denied: {url} is not on the allowlist", retryable=False)


class ProviderRouter:
    """Top-level provider orchestrator for the gateway."""

    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._provider_cache: Dict[tuple, LLMProvider] = {}
        self._max_retries = int(getattr(settings, "PROVIDER_RETRY_MAX", 3))
        self._base_delay = float(getattr(settings, "PROVIDER_RETRY_BASE_DELAY", 0.5))
        self._request_timeout = float(getattr(settings, "PROVIDER_REQUEST_TIMEOUT", 30.0))
        self._cb_threshold = int(getattr(settings, "PROVIDER_CIRCUIT_BREAKER_THRESHOLD", 5))
        self._cb_cooldown = float(getattr(settings, "PROVIDER_CIRCUIT_BREAKER_COOLDOWN", 30.0))
        self._egress_allowlist = self._parse_allowlist(
            getattr(settings, "PROVIDER_EGRESS_ALLOWLIST", "")
        )
        self._health_monitor = get_health_monitor()

    def _parse_allowlist(self, raw: str) -> List[str]:
        if not raw:
            return []
        return [d.strip().lower() for d in raw.split(",") if d.strip()]

    def _check_egress(self, url: str) -> None:
        validate_outbound_url(url, self._egress_allowlist)

    def _get_breaker(self, provider_key: str) -> CircuitBreaker:
        if provider_key not in self._breakers:
            self._breakers[provider_key] = CircuitBreaker(
                name=provider_key,
                failure_threshold=self._cb_threshold,
                cooldown_seconds=self._cb_cooldown,
            )
        return self._breakers[provider_key]

    def build_provider(self, provider_type: str, url: str, key: str, model: str) -> LLMProvider:
        """Construct a provider instance from config values."""
        if provider_type == "mock":
            return MockProvider()
        if provider_type in ("openai", "custom"):
            return OpenAIProvider(base_url=url, api_key=key, default_model=model)
        if provider_type == "anthropic":
            return AnthropicProvider(base_url=url, api_key=key, default_model=model)
        if provider_type == "gemini":
            return GeminiProvider(base_url=url, api_key=key, default_model=model or "gemini-1.5-flash")
        raise ProviderError(f"Unknown provider type: {provider_type}", retryable=False)

    def get_provider(self, provider_type: str, url: str, key: str, model: str) -> LLMProvider:
        """Cached build so HTTP sessions (TCP+TLS) are reused across requests."""
        cache_key = (provider_type, url, key, model)
        provider = self._provider_cache.get(cache_key)
        if provider is None:
            provider = self.build_provider(provider_type, url, key, model)
            if len(self._provider_cache) >= 32:
                self._provider_cache.clear()
            self._provider_cache[cache_key] = provider
        return provider

    def complete(
        self,
        messages: List[LLMMessage],
        primary_provider_type: str,
        primary_url: str,
        primary_key: str,
        primary_model: str,
        fallback_enabled: bool = False,
        fallback_provider_type: str = "mock",
        fallback_url: str = "",
        fallback_key: str = "",
        fallback_model: str = "",
    ) -> LLMResponse:
        """Route a completion through primary (with retry + CB), failing over to fallback."""

        # ── Try primary ───────────────────────────────────────────
        if primary_provider_type != "mock":
            if primary_url:
                self._check_egress(primary_url)

        primary = self.get_provider(primary_provider_type, primary_url, primary_key, primary_model)
        breaker = self._get_breaker(f"primary:{primary_provider_type}")
        start_time = time.monotonic()

        try:
            breaker.check()
            response = retry_with_backoff(
                fn=lambda: primary.complete(messages, primary_model, timeout=self._request_timeout),
                max_retries=self._max_retries,
                base_delay=self._base_delay,
                budget_seconds=self._request_timeout * 2,
            )
            latency_ms = (time.monotonic() - start_time) * 1000
            breaker.record_success()
            self._health_monitor.record_request(primary_provider_type, True, latency_ms)
            return response
        except CircuitBreakerOpen as exc:
            logger.warning("Primary circuit open: %s", exc)
            self._health_monitor.record_request(primary_provider_type, False, 0, str(exc))
        except (RetryBudgetExhausted, ProviderError) as exc:
            breaker.record_failure()
            latency_ms = (time.monotonic() - start_time) * 1000
            logger.error("Primary provider failed: %s", exc)
            self._health_monitor.record_request(primary_provider_type, False, latency_ms, str(exc))

        # ── Failover ──────────────────────────────────────────────
        if not fallback_enabled:
            raise ProviderError(
                "Primary provider failed and no fallback is configured", retryable=False
            )

        logger.warning("Failing over to fallback provider: %s", fallback_provider_type)

        if fallback_provider_type != "mock":
            if fallback_url:
                self._check_egress(fallback_url)

        fallback = self.get_provider(fallback_provider_type, fallback_url, fallback_key, fallback_model)
        fb_breaker = self._get_breaker(f"fallback:{fallback_provider_type}")
        fallback_start_time = time.monotonic()

        try:
            fb_breaker.check()
            response = retry_with_backoff(
                fn=lambda: fallback.complete(messages, fallback_model, timeout=self._request_timeout),
                max_retries=max(1, self._max_retries // 2),
                base_delay=self._base_delay,
                budget_seconds=self._request_timeout,
            )
            latency_ms = (time.monotonic() - fallback_start_time) * 1000
            fb_breaker.record_success()
            self._health_monitor.record_request(fallback_provider_type, True, latency_ms)
            response.provider = f"{fallback.name}(fallback)"
            return response
        except CircuitBreakerOpen as exc:
            self._health_monitor.record_request(fallback_provider_type, False, 0, str(exc))
            raise ProviderError(f"Fallback circuit also open: {exc}", retryable=False)
        except (RetryBudgetExhausted, ProviderError) as exc:
            latency_ms = (time.monotonic() - fallback_start_time) * 1000
            fb_breaker.record_failure()
            self._health_monitor.record_request(fallback_provider_type, False, latency_ms, str(exc))
            raise ProviderError(
                f"Both primary and fallback providers failed. Last: {exc}", retryable=False
            )

    def stream(
        self,
        messages: List[LLMMessage],
        primary_provider_type: str,
        primary_url: str,
        primary_key: str,
        primary_model: str,
        fallback_enabled: bool = False,
        fallback_provider_type: str = "mock",
        fallback_url: str = "",
        fallback_key: str = "",
        fallback_model: str = "",
    ):
        """Yield content chunks, honoring the same CB/egress rules as complete."""
        if primary_provider_type != "mock" and primary_url:
            self._check_egress(primary_url)
        primary = self.get_provider(primary_provider_type, primary_url, primary_key, primary_model)
        breaker = self._get_breaker(f"primary:{primary_provider_type}")
        try:
            breaker.check()
            yielded = False
            for chunk in primary.stream(messages, primary_model, timeout=self._request_timeout):
                yielded = True
                yield chunk
            if yielded:
                breaker.record_success()
                return
            breaker.record_success()
        except CircuitBreakerOpen as exc:
            logger.warning("Primary circuit open (stream): %s", exc)
        except ProviderError as exc:
            breaker.record_failure()
            logger.error("Primary stream failed: %s", exc)
        if not fallback_enabled:
            raise ProviderError("Primary stream failed and no fallback is configured", retryable=False)
        logger.warning("Failing over stream to fallback: %s", fallback_provider_type)
        if fallback_provider_type != "mock" and fallback_url:
            self._check_egress(fallback_url)
        fallback = self.get_provider(fallback_provider_type, fallback_url, fallback_key, fallback_model)
        fb_breaker = self._get_breaker(f"fallback:{fallback_provider_type}")
        fb_breaker.check()
        for chunk in fallback.stream(messages, fallback_model, timeout=self._request_timeout):
            yield chunk
        fb_breaker.record_success()

    def get_circuit_states(self) -> Dict[str, dict]:
        """Return current circuit breaker states for observability."""
        return {name: cb.to_dict() for name, cb in self._breakers.items()}

    def get_provider_health(self) -> Dict[str, dict]:
        """Return health metrics for all providers."""
        return {name: metrics.to_dict() for name, metrics in self._health_monitor.get_all_health().items()}


def assert_https_public_host(url: str) -> None:
    """Shared egress check: HTTPS scheme, resolvable hostname, all IPs globally routable.

    Raises ``ValueError``; used at gateway-config write time and (wrapped in
    ``EgressDenied``) immediately before outbound dispatch.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Outbound model URL must be HTTPS with a hostname")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve outbound model hostname: {parsed.hostname}") from exc
    if any(not ipaddress.ip_address(address[4][0]).is_global for address in addresses):
        raise ValueError("Outbound model URL resolves to a non-public network address")


def validate_outbound_url(url: str, allowlist: List[str]) -> None:
    """Fail-closed validation performed immediately before outbound dispatch."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise EgressDenied(url)
    host = parsed.hostname.lower()
    if not allowlist or not any(host == allowed or host.endswith("." + allowed) for allowed in allowlist):
        raise EgressDenied(url)
    try:
        assert_https_public_host(url)
    except ValueError as exc:
        raise EgressDenied(str(exc)) from exc