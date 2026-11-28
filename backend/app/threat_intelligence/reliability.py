"""
AutoSOC - Threat Intelligence Provider Reliability & Operational Status (Day 11)

Implements bounded retry policy with exponential backoff + Retry-After support,
per-provider circuit breaker with half-open cooldown recovery, and sanitized
operational status diagnostics without exposing credentials or raw data.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import time
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ProviderOperationalStateEnum(str, Enum):
    """Operational availability classification for a TI provider."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"


class CircuitBreakerStateEnum(str, Enum):
    """Per-provider circuit-breaker state machine."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class ProviderFailureCategoryEnum(str, Enum):
    """Sanitized failure classification (never exposes secrets or raw payloads)."""

    NONE = "none"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    UNAVAILABLE = "unavailable"
    VALIDATION_ERROR = "validation_error"
    MALFORMED_RESPONSE = "malformed_response"
    UNCONFIGURED = "unconfigured"


class ProviderReliabilityPolicy(BaseModel):
    """Validated, bounded retry and circuit-breaker policy for external TI lookups."""

    model_config = ConfigDict(extra="forbid")

    max_retries: int = Field(default=2, ge=0, le=5)
    retry_base_delay_seconds: float = Field(default=0.25, ge=0.0, le=10.0)
    retry_max_delay_seconds: float = Field(default=5.0, ge=0.0, le=30.0)
    circuit_breaker_threshold: int = Field(default=3, ge=1, le=50)
    circuit_breaker_cooldown_seconds: float = Field(default=60.0, ge=1.0, le=3600.0)

    def compute_backoff_delay(
        self, retry_index: int, retry_after_seconds: Optional[float] = None
    ) -> float:
        """
        Compute bounded exponential backoff for retry attempt `retry_index` (0-based),
        honoring provider Retry-After hints capped at `retry_max_delay_seconds`.
        """
        exp = self.retry_base_delay_seconds * (2 ** max(0, retry_index))
        bounded = min(self.retry_max_delay_seconds, max(0.0, exp))
        if (
            retry_after_seconds is not None
            and not isinstance(retry_after_seconds, bool)
            and retry_after_seconds > 0
        ):
            return min(self.retry_max_delay_seconds, max(bounded, float(retry_after_seconds)))
        return bounded


class ProviderOperationalStatus(BaseModel):
    """Safe, credential-free operational snapshot for one TI provider."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    provider_version: str
    enabled: bool
    configured: bool
    operational_state: ProviderOperationalStateEnum
    circuit_state: CircuitBreakerStateEnum
    consecutive_failures: int = Field(default=0, ge=0)
    total_requests: int = Field(default=0, ge=0)
    total_failures: int = Field(default=0, ge=0)
    total_retries: int = Field(default=0, ge=0)
    last_success_at: Optional[str] = None
    last_failure_at: Optional[str] = None
    last_failure_category: ProviderFailureCategoryEnum = ProviderFailureCategoryEnum.NONE
    cooldown_remaining_seconds: Optional[float] = Field(default=None, ge=0.0)
    last_error_summary: Optional[str] = Field(default=None, max_length=256)


class ThreatIntelProvidersStatusResponse(BaseModel):
    """Versioned API response summarizing configured TI provider operational health."""

    model_config = ConfigDict(extra="forbid")

    ti_enabled: bool
    policy: Dict[str, Any] = Field(default_factory=dict)
    providers: List[ProviderOperationalStatus] = Field(default_factory=list)
    generated_at: str


@dataclass
class _ProviderCircuitState:
    provider_version: str = "unknown"
    circuit_state: CircuitBreakerStateEnum = CircuitBreakerStateEnum.CLOSED
    consecutive_failures: int = 0
    total_requests: int = 0
    total_failures: int = 0
    total_retries: int = 0
    last_success_at: Optional[str] = None
    last_failure_at: Optional[str] = None
    last_failure_category: ProviderFailureCategoryEnum = ProviderFailureCategoryEnum.NONE
    opened_at_monotonic: Optional[float] = None
    half_open_probe_in_flight: bool = False
    last_error_summary: Optional[str] = None


class ProviderReliabilityTracker:
    """
    In-process tracker maintaining bounded per-provider failure counters,
    circuit-breaker transitions (CLOSED -> OPEN -> HALF_OPEN -> CLOSED),
    and operational status snapshots.
    """

    def __init__(
        self,
        policy: Optional[ProviderReliabilityPolicy] = None,
        *,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._policy = policy or ProviderReliabilityPolicy()
        self._clock = clock or time.monotonic
        self._states: Dict[str, _ProviderCircuitState] = {}

    @property
    def policy(self) -> ProviderReliabilityPolicy:
        return self._policy

    def _get_state(self, provider_id: str, provider_version: str = "unknown") -> _ProviderCircuitState:
        key = provider_id.strip().lower()
        state = self._states.get(key)
        if state is None:
            state = _ProviderCircuitState(provider_version=provider_version)
            self._states[key] = state
        elif provider_version and provider_version != "unknown":
            state.provider_version = provider_version
        return state

    def can_execute(
        self, provider_id: str, provider_version: str = "unknown"
    ) -> tuple[bool, Optional[float]]:
        """
        Check circuit-breaker gate before invoking a provider.
        Returns (allowed, cooldown_remaining_seconds).
        """
        state = self._get_state(provider_id, provider_version)
        if state.circuit_state == CircuitBreakerStateEnum.CLOSED:
            return True, None

        if state.circuit_state == CircuitBreakerStateEnum.OPEN:
            opened_at = state.opened_at_monotonic
            elapsed = (self._clock() - opened_at) if opened_at is not None else 0.0
            remaining = self._policy.circuit_breaker_cooldown_seconds - elapsed
            if remaining > 0:
                return False, round(remaining, 3)
            # Cooldown expired: transition to HALF_OPEN for a single probe
            state.circuit_state = CircuitBreakerStateEnum.HALF_OPEN
            state.half_open_probe_in_flight = True
            return True, None

        # HALF_OPEN: allow only one concurrent probe at a time
        if state.half_open_probe_in_flight:
            return False, 0.0
        state.half_open_probe_in_flight = True
        return True, None

    def record_request(self, provider_id: str, provider_version: str = "unknown") -> None:
        state = self._get_state(provider_id, provider_version)
        state.total_requests += 1

    def record_retry(self, provider_id: str, provider_version: str = "unknown") -> None:
        state = self._get_state(provider_id, provider_version)
        state.total_retries += 1

    def record_success(self, provider_id: str, provider_version: str = "unknown") -> None:
        """Record successful or healthy reachable response (resets breaker)."""
        state = self._get_state(provider_id, provider_version)
        state.circuit_state = CircuitBreakerStateEnum.CLOSED
        state.consecutive_failures = 0
        state.opened_at_monotonic = None
        state.half_open_probe_in_flight = False
        state.last_success_at = _utc_now_iso()
        state.last_failure_category = ProviderFailureCategoryEnum.NONE
        state.last_error_summary = None

    def record_failure(
        self,
        provider_id: str,
        provider_version: str = "unknown",
        *,
        category: ProviderFailureCategoryEnum,
        error_summary: Optional[str] = None,
        counts_toward_breaker: bool = True,
    ) -> None:
        """Record a sanitized failure and advance circuit breaker if threshold reached."""
        state = self._get_state(provider_id, provider_version)
        state.total_failures += 1
        state.last_failure_at = _utc_now_iso()
        state.last_failure_category = category
        state.last_error_summary = error_summary[:256] if error_summary else None

        if counts_toward_breaker:
            was_half_open = state.circuit_state == CircuitBreakerStateEnum.HALF_OPEN
            state.consecutive_failures += 1
            if was_half_open or state.consecutive_failures >= self._policy.circuit_breaker_threshold:
                state.circuit_state = CircuitBreakerStateEnum.OPEN
                state.opened_at_monotonic = self._clock()
                state.half_open_probe_in_flight = False
        else:
            state.half_open_probe_in_flight = False

    def record_health_check(
        self,
        provider_id: str,
        *,
        healthy: bool,
        provider_version: str = "unknown",
        error_summary: Optional[str] = None,
    ) -> None:
        """Update circuit state explicitly from a health-check probe."""
        if healthy:
            self.record_success(provider_id, provider_version)
        else:
            self.record_failure(
                provider_id,
                provider_version,
                category=ProviderFailureCategoryEnum.UNAVAILABLE,
                error_summary=error_summary or f"Health check failed for '{provider_id}'",
                counts_toward_breaker=True,
            )

    def snapshot_status(
        self,
        provider_id: str,
        *,
        provider_version: str,
        enabled: bool,
        configured: bool,
    ) -> ProviderOperationalStatus:
        """Return a sanitized operational snapshot without mutating probe locks."""
        state = self._get_state(provider_id, provider_version)
        effective_circuit = state.circuit_state
        cooldown_remaining: Optional[float] = None

        if effective_circuit == CircuitBreakerStateEnum.OPEN:
            opened_at = state.opened_at_monotonic
            elapsed = (self._clock() - opened_at) if opened_at is not None else 0.0
            remaining = self._policy.circuit_breaker_cooldown_seconds - elapsed
            if remaining > 0:
                cooldown_remaining = round(remaining, 3)
            else:
                effective_circuit = CircuitBreakerStateEnum.HALF_OPEN
                cooldown_remaining = 0.0

        if not enabled:
            op_state = ProviderOperationalStateEnum.DISABLED
            failure_cat = state.last_failure_category
        elif not configured:
            op_state = ProviderOperationalStateEnum.UNAVAILABLE
            failure_cat = ProviderFailureCategoryEnum.UNCONFIGURED
        elif effective_circuit == CircuitBreakerStateEnum.OPEN:
            op_state = ProviderOperationalStateEnum.UNAVAILABLE
            failure_cat = state.last_failure_category
        elif effective_circuit == CircuitBreakerStateEnum.HALF_OPEN or state.consecutive_failures > 0:
            op_state = ProviderOperationalStateEnum.DEGRADED
            failure_cat = state.last_failure_category
        else:
            op_state = ProviderOperationalStateEnum.HEALTHY
            failure_cat = state.last_failure_category

        return ProviderOperationalStatus(
            provider=provider_id,
            provider_version=state.provider_version or provider_version,
            enabled=enabled,
            configured=configured,
            operational_state=op_state,
            circuit_state=effective_circuit,
            consecutive_failures=state.consecutive_failures,
            total_requests=state.total_requests,
            total_failures=state.total_failures,
            total_retries=state.total_retries,
            last_success_at=state.last_success_at,
            last_failure_at=state.last_failure_at,
            last_failure_category=failure_cat,
            cooldown_remaining_seconds=cooldown_remaining,
            last_error_summary=state.last_error_summary,
        )
