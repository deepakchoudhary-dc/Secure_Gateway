"""
Provider health monitoring for multi-provider deployments.

Tracks provider availability, response times, error rates, and provides
health status for routing decisions and observability.
"""

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ProviderHealthMetrics:
    """Health metrics for a single provider."""
    provider_name: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_latency_ms: float = 0.0
    last_request_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    last_failure_time: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 1.0
        return self.successful_requests / self.total_requests

    @property
    def average_latency_ms(self) -> float:
        if self.successful_requests == 0:
            return 0.0
        return self.total_latency_ms / self.successful_requests

    @property
    def is_healthy(self) -> bool:
        """Basic health check: provider is healthy if success rate > 80% and consecutive failures < 3."""
        if self.total_requests < 5:
            return True  # Not enough data to determine health
        return self.success_rate > 0.8 and self.consecutive_failures < 3

    def to_dict(self) -> Dict:
        return {
            "provider_name": self.provider_name,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": round(self.success_rate, 3),
            "average_latency_ms": round(self.average_latency_ms, 2),
            "last_request_time": self.last_request_time.isoformat() if self.last_request_time else None,
            "last_success_time": self.last_success_time.isoformat() if self.last_success_time else None,
            "last_failure_time": self.last_failure_time.isoformat() if self.last_failure_time else None,
            "last_error": self.last_error,
            "consecutive_failures": self.consecutive_failures,
            "consecutive_successes": self.consecutive_successes,
            "is_healthy": self.is_healthy,
        }


class ProviderHealthMonitor:
    """Centralized health monitoring for all LLM providers."""

    def __init__(self):
        self._metrics: Dict[str, ProviderHealthMetrics] = {}
        self._lock = threading.Lock()
        self._retention_hours = 24  # Keep metrics for 24 hours

    def record_request(self, provider_name: str, success: bool, latency_ms: float, error: Optional[str] = None) -> None:
        """Record a provider request with its outcome."""
        with self._lock:
            if provider_name not in self._metrics:
                self._metrics[provider_name] = ProviderHealthMetrics(provider_name=provider_name)

            metrics = self._metrics[provider_name]
            now = datetime.now(timezone.utc)
            metrics.total_requests += 1
            metrics.last_request_time = now

            if success:
                metrics.successful_requests += 1
                metrics.total_latency_ms += latency_ms
                metrics.last_success_time = now
                metrics.consecutive_successes += 1
                metrics.consecutive_failures = 0
                metrics.last_error = None
            else:
                metrics.failed_requests += 1
                metrics.last_failure_time = now
                metrics.consecutive_failures += 1
                metrics.consecutive_successes = 0
                metrics.last_error = error

            logger.debug(
                "Provider %s: success=%s, latency=%.2fms, total=%d, success_rate=%.2f",
                provider_name, success, latency_ms, metrics.total_requests, metrics.success_rate
            )

    def get_health(self, provider_name: str) -> Optional[ProviderHealthMetrics]:
        """Get health metrics for a specific provider."""
        with self._lock:
            return self._metrics.get(provider_name)

    def get_all_health(self) -> Dict[str, ProviderHealthMetrics]:
        """Get health metrics for all providers."""
        with self._lock:
            return dict(self._metrics)

    def get_healthy_providers(self) -> List[str]:
        """Get list of provider names that are currently healthy."""
        with self._lock:
            return [name for name, metrics in self._metrics.items() if metrics.is_healthy]

    def reset_metrics(self, provider_name: Optional[str] = None) -> None:
        """Reset metrics for a specific provider or all providers."""
        with self._lock:
            if provider_name:
                if provider_name in self._metrics:
                    self._metrics[provider_name] = ProviderHealthMetrics(provider_name=provider_name)
                    logger.info("Reset health metrics for provider: %s", provider_name)
            else:
                self._metrics.clear()
                logger.info("Reset health metrics for all providers")

    def cleanup_old_metrics(self) -> None:
        """Remove metrics for providers that haven't been used recently."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self._retention_hours)
        with self._lock:
            to_remove = [
                name for name, metrics in self._metrics.items()
                if metrics.last_request_time and metrics.last_request_time < cutoff
            ]
            for name in to_remove:
                del self._metrics[name]
                logger.debug("Cleaned up old metrics for provider: %s", name)


# Global singleton
_monitor: Optional[ProviderHealthMonitor] = None
_monitor_lock = threading.Lock()


def get_health_monitor() -> ProviderHealthMonitor:
    """Get the global health monitor instance."""
    global _monitor
    if _monitor is None:
        with _monitor_lock:
            if _monitor is None:
                _monitor = ProviderHealthMonitor()
    return _monitor
