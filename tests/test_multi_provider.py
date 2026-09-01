"""
Tests for multi-provider functionality including circuit breakers, retry logic,
and health monitoring.
"""

import pytest
from src.providers.router_provider import ProviderRouter
from src.providers.circuit_breaker import CircuitBreaker, CircuitBreakerOpen
from src.providers.health_monitor import ProviderHealthMonitor, get_health_monitor
from src.providers.retry import retry_with_backoff, RetryBudgetExhausted
from src.providers.base import ProviderError


def test_circuit_breaker_state_transitions():
    """Test circuit breaker state machine transitions."""
    breaker = CircuitBreaker(name="test", failure_threshold=3, cooldown_seconds=1.0)

    # Initially closed
    assert breaker.state.value == "closed"
    assert breaker.to_dict()["failure_count"] == 0

    # Record failures up to threshold
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state.value == "closed"
    assert breaker.to_dict()["failure_count"] == 2

    # Third failure should open the circuit
    breaker.record_failure()
    assert breaker.state.value == "open"
    assert breaker.to_dict()["failure_count"] == 3

    # Check should raise when circuit is open
    with pytest.raises(CircuitBreakerOpen):
        breaker.check()

    # Success should close the circuit
    breaker.record_success()
    assert breaker.state.value == "closed"
    assert breaker.to_dict()["failure_count"] == 0


def test_circuit_breaker_half_open():
    """Test circuit breaker half-open state after cooldown."""
    import time

    breaker = CircuitBreaker(name="test", failure_threshold=2, cooldown_seconds=0.1, half_open_max_attempts=2)

    # Open the circuit
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state.value == "open"

    # Wait for cooldown
    time.sleep(0.15)

    # Should transition to half-open
    assert breaker.state.value == "half_open"

    # First half-open attempt should be allowed
    breaker.check()
    assert breaker.to_dict()["half_open_attempts"] == 1

    # Second half-open attempt should be allowed
    breaker.check()
    assert breaker.to_dict()["half_open_attempts"] == 2

    # Third attempt should be blocked
    with pytest.raises(CircuitBreakerOpen):
        breaker.check()


def test_retry_with_backoff_success():
    """Test retry logic with successful retry."""
    attempts = []

    def failing_once():
        attempts.append(1)
        if len(attempts) == 1:
            raise ProviderError("Temporary failure", retryable=True)
        return "success"

    result = retry_with_backoff(failing_once, max_retries=2, base_delay=0.01)
    assert result == "success"
    assert len(attempts) == 2


def test_retry_with_backoff_exhausted():
    """Test retry logic when all attempts fail."""
    def always_failing():
        raise ProviderError("Permanent failure", retryable=True)

    with pytest.raises(RetryBudgetExhausted):
        retry_with_backoff(always_failing, max_retries=2, base_delay=0.01)


def test_retry_non_retryable_error():
    """Test that non-retryable errors are not retried."""
    attempts = []

    def non_retryable_failure():
        attempts.append(1)
        raise ProviderError("Bad request", retryable=False, status_code=400)

    with pytest.raises(ProviderError):
        retry_with_backoff(non_retryable_failure, max_retries=3, base_delay=0.01)

    assert len(attempts) == 1  # Should not retry


def test_health_monitor_metrics():
    """Test provider health monitoring."""
    monitor = ProviderHealthMonitor()

    # Record successful request
    monitor.record_request("openai", success=True, latency_ms=150.5)
    health = monitor.get_health("openai")

    assert health is not None
    assert health.total_requests == 1
    assert health.successful_requests == 1
    assert health.failed_requests == 0
    assert health.success_rate == 1.0
    assert health.average_latency_ms == 150.5
    assert health.is_healthy is True

    # Record failed request
    monitor.record_request("openai", success=False, latency_ms=0, error="timeout")
    health = monitor.get_health("openai")

    assert health.total_requests == 2
    assert health.successful_requests == 1
    assert health.failed_requests == 1
    assert health.success_rate == 0.5
    assert health.consecutive_failures == 1
    assert health.last_error == "timeout"


def test_health_monitor_healthy_threshold():
    """Test health threshold for provider health status."""
    monitor = ProviderHealthMonitor()

    # Record enough successful requests to establish baseline
    for _ in range(10):
        monitor.record_request("openai", success=True, latency_ms=100.0)

    health = monitor.get_health("openai")
    assert health.is_healthy is True

    # Record failures to drop below 80% success rate
    for _ in range(5):
        monitor.record_request("openai", success=False, latency_ms=0, error="error")

    health = monitor.get_health("openai")
    assert health.success_rate < 0.8
    assert health.is_healthy is False


def test_health_monitor_consecutive_failures():
    """Test that consecutive failures affect health status."""
    monitor = ProviderHealthMonitor()

    # Establish baseline
    for _ in range(10):
        monitor.record_request("openai", success=True, latency_ms=100.0)

    # Record 3 consecutive failures
    for _ in range(3):
        monitor.record_request("openai", success=False, latency_ms=0, error="error")

    health = monitor.get_health("openai")
    assert health.consecutive_failures == 3
    assert health.is_healthy is False


def test_health_monitor_reset():
    """Test resetting health metrics."""
    monitor = ProviderHealthMonitor()

    monitor.record_request("openai", success=True, latency_ms=100.0)
    monitor.record_request("openai", success=False, latency_ms=0, error="error")

    monitor.reset_metrics("openai")
    health = monitor.get_health("openai")

    assert health.total_requests == 0
    assert health.successful_requests == 0
    assert health.failed_requests == 0


def test_provider_router_circuit_breaker_integration():
    """Test that provider router integrates with circuit breakers."""
    router = ProviderRouter()

    # Get circuit breaker for primary provider
    breaker = router._get_breaker("primary:openai")
    assert breaker is not None
    assert breaker.name == "primary:openai"

    # Record some state
    breaker.record_failure()
    breaker.record_failure()

    # Get circuit states should include our breaker
    states = router.get_circuit_states()
    assert "primary:openai" in states
    assert states["primary:openai"]["failure_count"] == 2


def test_provider_router_health_monitoring():
    """Test that provider router integrates with health monitoring."""
    router = ProviderRouter()

    # Access health monitor through router
    health = router.get_provider_health()
    assert isinstance(health, dict)
    initial = health.get("openai", {}).get("total_requests", 0) if isinstance(health.get("openai"), dict) else 0
    # Handle both dict and object forms
    if isinstance(health.get("openai"), dict):
        initial = health["openai"]["total_requests"]
    elif hasattr(health.get("openai"), "total_requests"):
        initial = health["openai"].total_requests
    else:
        initial = 0

    # Record some metrics
    router._health_monitor.record_request("openai", success=True, latency_ms=200.0)

    # Check that metrics are reflected (isolated from prior tests)
    health = router.get_provider_health()
    assert "openai" in health
    val = health["openai"]["total_requests"] if isinstance(health["openai"], dict) else health["openai"].total_requests
    assert val == initial + 1


def test_response_cache_stats():
    """Test response cache statistics."""
    from src.gateway.response_cache import stats, cache_key, put, get, reset_stats

    # Reset stats first
    reset_stats()

    # Create a cache key and store a response
    key = cache_key("default", "user1", "test prompt", None, None, "gpt-3.5-turbo")
    put(key, "test response")

    # Cache miss
    result = get("different_key")
    stats_result = stats()
    assert stats_result["misses"] == 1
    assert stats_result["hits"] == 0

    # Cache hit
    result = get(key)
    stats_result = stats()
    assert stats_result["hits"] == 1
    assert stats_result["misses"] == 1
    assert stats_result["hit_rate"] == 0.5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
