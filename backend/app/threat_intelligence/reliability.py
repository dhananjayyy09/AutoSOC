"""
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

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


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
    """

    def __init__(
        self,
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
