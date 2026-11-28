"""
<<<<<<< HEAD
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
=======
AutoSOC - Threat Intelligence Provider Reliability & Security Semantics (Day 11)

Defines unified operational-state, retry, circuit-breaker, safe-request, and
evidence/verdict invariants shared by `ThreatIntelOrchestrator` and
`ThreatIntelObservablePipeline` without creating a second orchestration path.

Key Security Guarantees:
  1. Operational failures (`unavailable`, `timeout`, `rate_limited`, `retry_exhausted`,
     `circuit_open`, `provider_disabled`, `malformed_response`) NEVER convert to `benign`
     or `malicious`; observable verdicts stay `unknown`.
  2. `no_result` / `no_data` is distinct from operational failures, does not trip
     circuit breakers, and never infers `benign`.
  3. Retries apply only to transient operational failures and NEVER duplicate evidence
     or references across attempts.
  4. Outbound provider requests allow ONLY `observable_type` and `normalized_value`
     (plus bounded `timeout_seconds` where used internally) — never raw payloads,
     event IDs, user IDs, unrelated command lines, or credentials.
"""

from enum import Enum
import time
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    List,
    Optional,
    Sequence,
    Tuple,
)

from app.events.schemas import BaseModel, Field
from app.events.validation import ValidationErrorCategory, ValidationIssue
from app.threat_intelligence.provider_contract import (
    ObservableLookupRequest,
    ObservableLookupResult,
    ProviderLookupStatusEnum,
    ProviderReference,
    utc_now_iso,
    validate_observable_for_lookup,
)
from app.threat_intelligence.schemas import ObservableTypeEnum, ObservableVerdictEnum

RETRYABLE_STATUS_VALUES: FrozenSet[str] = frozenset(
    {"timeout", "unavailable", "rate_limited"}
)

OPERATIONAL_FAILURE_STATUS_VALUES: FrozenSet[str] = frozenset(
    {
        "timeout",
        "unavailable",
        "rate_limited",
        "retry_exhausted",
        "circuit_open",
        "provider_disabled",
        "malformed_response",
        "invalid_response",
        "failed",
    }
)

NON_FAILURE_NON_FOUND_STATUS_VALUES: FrozenSet[str] = frozenset(
    {
        "no_result",
        "no_data",
        "unsupported_observable",
        "unsupported",
        "skipped",
        "skipped_limit",
        "offline_only",
    }
)

FORBIDDEN_OUTBOUND_REQUEST_KEYS: FrozenSet[str] = frozenset(
    {
        "raw_payload",
        "raw_event",
        "event_id",
        "source_event_id",
        "ingestion_id",
        "user",
        "user_name",
        "command_line",
        "credentials",
        "authorization",
        "api_key",
        "apikey",
        "secret",
        "token",
        "password",
        "headers",
    }
)


class ProviderOperationalStateEnum(str, Enum):
    """Operational health/availability state of a TI provider."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    RATE_LIMITED = "rate_limited"
    CIRCUIT_OPEN = "circuit_open"
    DISABLED = "disabled"
    UNCONFIGURED = "unconfigured"


class CircuitBreakerStateEnum(str, Enum):
    """Standard three-state circuit breaker FSM."""
>>>>>>> origin/feature/pranjal/day11

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


<<<<<<< HEAD
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
=======
class RetryPolicy(BaseModel):
    """
    Bounded retry configuration for transient TI provider failures.
    Default `max_attempts=1` maintains single-attempt behavior unless retries are enabled.
    """

    max_attempts: int = Field(
        default=1,
        ge=1,
        le=5,
        description="Total attempts including initial lookup (1 = no retries)",
    )

    def should_retry(self, status_value: str, attempt_number: int) -> bool:
        """Return True only for retryable transient statuses before max_attempts is reached."""
        if attempt_number >= self.max_attempts:
            return False
        return str(status_value).lower() in RETRYABLE_STATUS_VALUES


class _CircuitRecord:
    def __init__(self) -> None:
        self.state: CircuitBreakerStateEnum = CircuitBreakerStateEnum.CLOSED
        self.consecutive_failures: int = 0
        self.opened_at: Optional[float] = None
        self.last_failure_status: Optional[str] = None


class ProviderCircuitBreaker:
    """
    Per-provider circuit breaker preventing cascading failures while keeping
    observable verdicts strictly isolated from provider health.
>>>>>>> origin/feature/pranjal/day11
    """

    def __init__(
        self,
<<<<<<< HEAD
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
=======
        *,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self._failure_threshold = max(1, int(failure_threshold))
        self._cooldown_seconds = max(0.0, float(cooldown_seconds))
        self._clock = clock or time.monotonic
        self._records: Dict[str, _CircuitRecord] = {}

    def _get_record(self, provider_name: str) -> _CircuitRecord:
        key = provider_name.strip().lower()
        if key not in self._records:
            self._records[key] = _CircuitRecord()
        return self._records[key]

    def get_state(self, provider_name: str) -> CircuitBreakerStateEnum:
        rec = self._get_record(provider_name)
        if rec.state == CircuitBreakerStateEnum.OPEN and rec.opened_at is not None:
            if (self._clock() - rec.opened_at) >= self._cooldown_seconds:
                rec.state = CircuitBreakerStateEnum.HALF_OPEN
        return rec.state

    def allow_request(self, provider_name: str) -> bool:
        """Return True when CLOSED or HALF_OPEN (probe allowed); False when OPEN."""
        state = self.get_state(provider_name)
        return state != CircuitBreakerStateEnum.OPEN

    def record_success(self, provider_name: str) -> None:
        """Reset failure count and close circuit after a successful or clean no-data lookup."""
        rec = self._get_record(provider_name)
        rec.state = CircuitBreakerStateEnum.CLOSED
        rec.consecutive_failures = 0
        rec.opened_at = None
        rec.last_failure_status = None

    def record_failure(self, provider_name: str, status_value: str) -> CircuitBreakerStateEnum:
        """
        Record an operational failure. Non-failure statuses (`no_result`, `no_data`,
        `unsupported`, etc.) never increment failure count or open the circuit.
        """
        norm_status = str(status_value).lower()
        if norm_status not in OPERATIONAL_FAILURE_STATUS_VALUES:
            return self.get_state(provider_name)

        rec = self._get_record(provider_name)
        rec.last_failure_status = norm_status

        if rec.state == CircuitBreakerStateEnum.HALF_OPEN:
            rec.state = CircuitBreakerStateEnum.OPEN
            rec.opened_at = self._clock()
            return rec.state

        rec.consecutive_failures += 1
        if rec.consecutive_failures >= self._failure_threshold:
            rec.state = CircuitBreakerStateEnum.OPEN
            rec.opened_at = self._clock()
        return rec.state

    def get_operational_state(
        self,
        provider_name: str,
        *,
        enabled: bool = True,
        configured: bool = True,
    ) -> ProviderOperationalStateEnum:
        if not enabled:
            return ProviderOperationalStateEnum.DISABLED
        if not configured:
            return ProviderOperationalStateEnum.UNCONFIGURED
        rec = self._get_record(provider_name)
        cb_state = self.get_state(provider_name)
        if cb_state == CircuitBreakerStateEnum.OPEN:
            return ProviderOperationalStateEnum.CIRCUIT_OPEN
        if rec.last_failure_status == "rate_limited" and rec.consecutive_failures > 0:
            return ProviderOperationalStateEnum.RATE_LIMITED
        if cb_state == CircuitBreakerStateEnum.HALF_OPEN or rec.consecutive_failures > 0:
            return ProviderOperationalStateEnum.DEGRADED
        return ProviderOperationalStateEnum.HEALTHY


def deduplicate_references(references: Sequence[Any]) -> List[Any]:
    """Deduplicate ProviderReference objects or dicts while preserving deterministic order."""
    seen: set[Tuple[Any, Any, Any]] = set()
    unique: List[Any] = []
    for ref in references:
        if isinstance(ref, dict):
            key = (ref.get("source_name"), ref.get("reference_id"), ref.get("reference_url"))
        else:
            key = (
                getattr(ref, "source_name", None),
                getattr(ref, "reference_id", None),
                getattr(ref, "reference_url", None),
            )
        if key not in seen:
            seen.add(key)
            unique.append(ref)
    return unique


def validate_safe_provider_request(
    observable_type: Any,
    value: Any,
    *,
    extra_payload: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Optional[ObservableLookupRequest], Optional[str], bool]:
    """
    Validate that an outbound provider request contains ONLY valid observable_type
    and normalized_value, with zero raw event, event ID, user, command line, or secret leakage.
    Returns: (is_valid, minimal_request, error_message, is_unsupported_type)
    """
    if extra_payload is not None:
        if not isinstance(extra_payload, dict):
            return False, None, "Provider request payload must be a dictionary", False
        forbidden_present = sorted(
            str(k)
            for k in extra_payload.keys()
            if str(k).lower() in FORBIDDEN_OUTBOUND_REQUEST_KEYS
        )
        if forbidden_present:
            return (
                False,
                None,
                f"Rejected unsafe provider request containing forbidden fields: {', '.join(forbidden_present)}",
                False,
            )

    is_valid, obs_type, canonical_val, err_msg = validate_observable_for_lookup(
        observable_type, value
    )
    if not is_valid or obs_type is None or canonical_val is None:
        is_unsupported = obs_type is None
        return (
            False,
            None,
            err_msg or "Rejected invalid observable pre-lookup",
            is_unsupported,
        )

    return (
        True,
        ObservableLookupRequest(observable_type=obs_type, normalized_value=canonical_val),
        None,
        False,
    )


def enforce_verdict_and_evidence_invariants(
    result: ObservableLookupResult,
) -> ObservableLookupResult:
    """
    Enforce Day 11 security invariants on any ObservableLookupResult:
      - Operational failures and non-found statuses MUST keep verdict='unknown' and confidence=None.
      - Non-unknown verdicts without supporting evidence/references are downgraded to malformed_response.
      - References are deduplicated.
    """
    status_val = (
        result.lookup_status.value
        if hasattr(result.lookup_status, "value")
        else str(result.lookup_status)
    )
    deduped_refs = deduplicate_references(result.references or [])

    if status_val != ProviderLookupStatusEnum.FOUND.value:
        if result.verdict != ObservableVerdictEnum.UNKNOWN or result.confidence is not None:
            return ObservableLookupResult(
                provider_name=result.provider_name,
                provider_version=result.provider_version,
                observable_type=result.observable_type,
                normalized_value=result.normalized_value,
                lookup_status=result.lookup_status,
                verdict=ObservableVerdictEnum.UNKNOWN,
                confidence=None,
                evidence={},
                references=[],
                lookup_timestamp=result.lookup_timestamp,
                warnings=list(result.warnings or []),
                errors=list(result.errors or []),
                live_lookup_performed=False,
            )
        return result

    has_evidence = bool(result.evidence) or bool(deduped_refs)
    if result.verdict != ObservableVerdictEnum.UNKNOWN and not has_evidence:
        return ObservableLookupResult(
            provider_name=result.provider_name,
            provider_version=result.provider_version,
            observable_type=result.observable_type,
            normalized_value=result.normalized_value,
            lookup_status=ProviderLookupStatusEnum.MALFORMED_RESPONSE,
            verdict=ObservableVerdictEnum.UNKNOWN,
            confidence=None,
            evidence={},
            references=[],
            lookup_timestamp=result.lookup_timestamp,
            warnings=list(result.warnings or []),
            errors=[
                ValidationIssue(
                    category=ValidationErrorCategory.MALFORMED_PAYLOAD,
                    field="evidence",
                    message=f"Verdict '{result.verdict.value}' rejected: missing supporting evidence or references",
                    severity="error",
                )
            ],
            live_lookup_performed=result.live_lookup_performed,
        )

    if len(deduped_refs) != len(result.references or []):
        return ObservableLookupResult(
            provider_name=result.provider_name,
            provider_version=result.provider_version,
            observable_type=result.observable_type,
            normalized_value=result.normalized_value,
            lookup_status=result.lookup_status,
            verdict=result.verdict,
            confidence=result.confidence,
            evidence=dict(result.evidence or {}),
            references=deduped_refs,
            lookup_timestamp=result.lookup_timestamp,
            warnings=list(result.warnings or []),
            errors=list(result.errors or []),
            live_lookup_performed=result.live_lookup_performed,
        )
    return result


def execute_lookup_with_reliability(
    *,
    provider_name: str,
    provider_version: str,
    is_live_lookup: bool,
    enabled: bool,
    supported_types: FrozenSet[ObservableTypeEnum],
    request: ObservableLookupRequest,
    call_fn: Callable[[ObservableLookupRequest, str], ObservableLookupResult],
    retry_policy: Optional[RetryPolicy] = None,
    circuit_breaker: Optional[ProviderCircuitBreaker] = None,
    lookup_timestamp: Optional[str] = None,
) -> ObservableLookupResult:
    """
    Execute a synchronous provider lookup enforcing disabled-check, circuit breaker,
    bounded retries without evidence/reference duplication, and Day 11 security invariants.
    """
    ts = lookup_timestamp or utc_now_iso()
    policy = retry_policy or RetryPolicy(max_attempts=1)

    if not enabled:
        return ObservableLookupResult(
            provider_name=provider_name,
            provider_version=provider_version,
            observable_type=request.observable_type,
            normalized_value=request.normalized_value,
            lookup_status=ProviderLookupStatusEnum.PROVIDER_DISABLED,
            verdict=ObservableVerdictEnum.UNKNOWN,
            confidence=None,
            evidence={},
            references=[],
            lookup_timestamp=ts,
            warnings=[
                ValidationIssue(
                    category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
                    field="provider",
                    message=f"Provider '{provider_name}' is disabled",
                    severity="warning",
                )
            ],
            live_lookup_performed=False,
        )

    if request.observable_type not in supported_types:
        return ObservableLookupResult(
            provider_name=provider_name,
            provider_version=provider_version,
            observable_type=request.observable_type,
            normalized_value=request.normalized_value,
            lookup_status=ProviderLookupStatusEnum.UNSUPPORTED_OBSERVABLE,
            verdict=ObservableVerdictEnum.UNKNOWN,
            confidence=None,
            evidence={},
            references=[],
            lookup_timestamp=ts,
            warnings=[
                ValidationIssue(
                    category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
                    field="observable_type",
                    message=f"Provider '{provider_name}' does not support '{request.observable_type.value}' lookups",
                    severity="warning",
                )
            ],
            live_lookup_performed=False,
        )

    if circuit_breaker is not None and not circuit_breaker.allow_request(provider_name):
        return ObservableLookupResult(
            provider_name=provider_name,
            provider_version=provider_version,
            observable_type=request.observable_type,
            normalized_value=request.normalized_value,
            lookup_status=ProviderLookupStatusEnum.CIRCUIT_OPEN,
            verdict=ObservableVerdictEnum.UNKNOWN,
            confidence=None,
            evidence={},
            references=[],
            lookup_timestamp=ts,
            errors=[
                ValidationIssue(
                    category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                    field="provider",
                    message=f"Circuit breaker OPEN for provider '{provider_name}'; lookup short-circuited",
                    severity="error",
                )
            ],
            live_lookup_performed=False,
        )

    last_result: Optional[ObservableLookupResult] = None
    attempts_made = 0

    for attempt in range(1, policy.max_attempts + 1):
        attempts_made = attempt
        try:
            raw_res = call_fn(request, ts)
            last_result = enforce_verdict_and_evidence_invariants(raw_res)
        except Exception as exc:
            last_result = ObservableLookupResult(
                provider_name=provider_name,
                provider_version=provider_version,
                observable_type=request.observable_type,
                normalized_value=request.normalized_value,
                lookup_status=ProviderLookupStatusEnum.FAILED,
                verdict=ObservableVerdictEnum.UNKNOWN,
                confidence=None,
                evidence={},
                references=[],
                lookup_timestamp=ts,
                errors=[
                    ValidationIssue(
                        category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                        field="provider",
                        message=f"Provider '{provider_name}' raised {type(exc).__name__}",
                        severity="error",
                    )
                ],
                live_lookup_performed=is_live_lookup,
            )

        status_val = last_result.lookup_status.value
        if status_val not in OPERATIONAL_FAILURE_STATUS_VALUES:
            if circuit_breaker is not None:
                circuit_breaker.record_success(provider_name)
            return last_result

        if not policy.should_retry(status_val, attempt):
            break

    # Failure path after attempts concluded
    assert last_result is not None
    final_status = last_result.lookup_status
    final_errors = list(last_result.errors or [])

    if (
        attempts_made > 1
        and final_status.value in RETRYABLE_STATUS_VALUES
    ):
        last_reason = final_status.value
        final_status = ProviderLookupStatusEnum.RETRY_EXHAUSTED
        final_errors = [
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field="provider",
                message=(
                    f"Provider '{provider_name}' exhausted {attempts_made} retry attempts "
                    f"(last failure: {last_reason})"
                ),
                severity="error",
            )
        ]

    if circuit_breaker is not None:
        circuit_breaker.record_failure(provider_name, final_status.value)

    return ObservableLookupResult(
        provider_name=last_result.provider_name,
        provider_version=last_result.provider_version,
        observable_type=last_result.observable_type,
        normalized_value=last_result.normalized_value,
        lookup_status=final_status,
        verdict=ObservableVerdictEnum.UNKNOWN,
        confidence=None,
        evidence={},
        references=[],
        lookup_timestamp=last_result.lookup_timestamp,
        warnings=list(last_result.warnings or []),
        errors=final_errors,
        live_lookup_performed=last_result.live_lookup_performed,
    )
>>>>>>> origin/feature/pranjal/day11
