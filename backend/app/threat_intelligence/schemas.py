"""
AutoSOC - Canonical Security Enrichment Contract (Day 9)

Single source of truth for security enrichment statuses, observable types,
factual classifications, provenance, and structured enrichment results.
Reuses `BaseModel` and `Field` from `app.events.schemas` and `ValidationIssue`
from `app.events.validation` without duplicating schema definitions.
"""

from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional

from app.events.schemas import PYDANTIC_V2, BaseModel, Field
from app.events.validation import ValidationIssue

if PYDANTIC_V2:
    from pydantic import ConfigDict, field_validator, model_validator

_FORBIDDEN_TI_KEYS: FrozenSet[str] = frozenset({"raw_payload", "raw_event"})


def contains_forbidden_ti_keys(obj: Any) -> bool:
    """Recursively ensure raw event payload keys never leak into TI payloads."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k) in _FORBIDDEN_TI_KEYS or contains_forbidden_ti_keys(v):
                return True
    elif isinstance(obj, list):
        return any(contains_forbidden_ti_keys(item) for item in obj)
    return False


class EnrichmentStatusEnum(str, Enum):
    """Deterministic enrichment lifecycle outcome for a normalized event."""

    ENRICHED = "enriched"
    ENRICHED_PARTIAL = "enriched_partial"
    NO_OBSERVABLES = "no_observables"
    SKIPPED = "skipped"
    FAILED = "failed"


class ObservableTypeEnum(str, Enum):
    """Supported observable types extracted from normalized security events."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"


class ObservableClassificationEnum(str, Enum):
    """
    Strictly factual, deterministic context classifications for observables.
    Does not assign malicious threat verdicts or reputation scores.
    """

    # IP classifications
    PRIVATE_RFC1918 = "private_rfc1918"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    DOCUMENTATION_TEST = "documentation_test"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    PUBLIC_ROUTABLE = "public_routable"

    # Domain classifications
    INTERNAL_OR_LOCAL = "internal_or_local"
    RESERVED_TEST_DOMAIN = "reserved_test_domain"
    EXTERNAL_FQDN = "external_fqdn"

    # URL classifications
    URL_HTTP = "url_http"
    URL_HTTPS = "url_https"

    # File hash classifications
    HASH_SHA256 = "hash_sha256"
    HASH_SHA1 = "hash_sha1"
    HASH_MD5 = "hash_md5"


class ObservableVerdictEnum(str, Enum):
    """
    Reputation/threat verdict for an observable.
    Offline deterministic enrichment strictly preserves `unknown`; external TI
    providers may assert `benign`, `suspicious`, or `malicious` only with evidence.
    """

    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ThreatIntelLookupStatusEnum(str, Enum):
    """Granular status for per-observable Threat Intelligence provider lookups."""

    SUCCESS = "success"
    NO_DATA = "no_data"
    CACHE_HIT = "cache_hit"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    RETRY_EXHAUSTED = "retry_exhausted"
    CIRCUIT_OPEN = "circuit_open"
    PROVIDER_DISABLED = "provider_disabled"
    INVALID_OBSERVABLE = "invalid_observable"
    INVALID_RESPONSE = "invalid_response"
    UNSUPPORTED = "unsupported"
    SKIPPED_LIMIT = "skipped_limit"
    OFFLINE_ONLY = "offline_only"


class EnrichmentProvenance(BaseModel):
    """
    Traceable provenance and deterministic rule evidence for an enriched observable.
    """

    source_event_id: Optional[str] = Field(
        default=None, description="UUID of source NormalizedSecurityEvent if present"
    )
    ingestion_id: str = Field(
        description="Originating delivery attempt UUID referencing raw evidence"
    )
    source_fields: List[str] = Field(
        default_factory=list,
        description="Ordered normalized field paths that produced this observable",
    )
    original_values: List[str] = Field(
        default_factory=list,
        description="Distinct raw observed values preserved verbatim (never executed)",
    )
    provider: str = Field(description="Enrichment provider identifier")
    provider_version: str = Field(description="Enrichment provider version")
    method: str = Field(description="Deterministic extraction/classification rule name")
    evidence: str = Field(
        description="Human-readable deterministic explanation grounded in factual properties"
    )
    live_lookup_performed: bool = Field(
        default=False,
        description="False for deterministic local enrichment; True only for live external TI lookups",
    )
    lookup_status: Optional[str] = Field(
        default=None,
        description="Consolidated lookup disposition (offline_only, success, cache_hit, timeout, etc.)",
    )
    lookup_timestamp: Optional[str] = Field(
        default=None,
        description="ISO 8601 UTC timestamp of external TI lookup or cache retrieval",
    )


class EnrichedObservable(BaseModel):
    """Single deduplicated, normalized observable with deterministic context and provenance."""

    observable_type: ObservableTypeEnum = Field(description="Observable category")
    normalized_value: str = Field(
        description="Canonical normalized observable string (lowercase/RFC 5952)"
    )
    original_value: str = Field(
        description="Primary untrusted observed value preserved verbatim"
    )
    classification: ObservableClassificationEnum = Field(
        description="Factual deterministic context classification"
    )
    verdict: ObservableVerdictEnum = Field(
        default=ObservableVerdictEnum.UNKNOWN,
        description="Threat verdict ('unknown' when no evidence-backed TI verdict exists)",
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Validated provider confidence score [0.0, 1.0] when evidence-backed",
    )
    lookup_status: Optional[str] = Field(
        default=None,
        description="Consolidated TI lookup status for this observable",
    )
    lookup_timestamp: Optional[str] = Field(
        default=None,
        description="ISO 8601 UTC timestamp when TI intelligence was resolved",
    )
    cached: Optional[bool] = Field(
        default=None,
        description="True when observable TI result was served from cache",
    )
    live_lookup_performed: Optional[bool] = Field(
        default=None,
        description="True only when a live external TI network call ran for this observable",
    )
    evidence_summary: Optional[str] = Field(
        default=None,
        description="Concise sanitized summary of supporting TI evidence",
    )
    references: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Sanitized provider reference metadata (source_name, reference_id, reference_url)",
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Deterministic structural attributes (e.g., ip_version, is_internal, tld, scheme, algorithm)",
    )
    provenance: EnrichmentProvenance = Field(
        description="Full provenance chain linking back to source event and fields"
    )


class ThreatIntelLookupRequest(BaseModel):
    """Normalized, bounded request passed to ThreatIntelProviderProtocol implementations."""

    if PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid")

    observable_type: ObservableTypeEnum
    normalized_value: str = Field(min_length=1, max_length=2048)
    source_event_id: Optional[str] = None
    ingestion_id: str = Field(min_length=1, max_length=36)
    timeout_seconds: float = Field(default=3.0, gt=0.0, le=30.0)


class ThreatIntelLookupResult(BaseModel):
    """
    Strictly validated external Threat Intelligence provider lookup response.
    Treats external provider data as untrusted and enforces evidence backing for
    any non-unknown verdict.
    """

    if PYDANTIC_V2:
        model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1, max_length=64)
    provider_version: str = Field(min_length=1, max_length=32)
    observable_type: ObservableTypeEnum
    normalized_value: str = Field(min_length=1, max_length=2048)
    lookup_status: ThreatIntelLookupStatusEnum
    verdict: ObservableVerdictEnum = ObservableVerdictEnum.UNKNOWN
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    evidence: Optional[str] = Field(default=None, max_length=512)
    references: List[Dict[str, Any]] = Field(default_factory=list, max_length=20)
    categories: List[str] = Field(default_factory=list, max_length=20)
    score: Optional[int] = Field(default=None, ge=0, le=100)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    lookup_timestamp: str = Field(min_length=1, max_length=64)
    live_lookup_performed: bool = False
    cache_hit: bool = False
    error_message: Optional[str] = Field(default=None, max_length=256)

    if PYDANTIC_V2:

        @field_validator("categories")
        @classmethod
        def validate_categories(cls, value: List[str]) -> List[str]:
            cleaned: List[str] = []
            for item in value[:20]:
                text = str(item).strip()
                if text and text not in cleaned:
                    cleaned.append(text[:64])
            return cleaned

        @model_validator(mode="after")
        def enforce_evidence_and_no_raw_leakage(self) -> "ThreatIntelLookupResult":
            self._check_invariants()
            return self

    else:

        def __init__(self, **data: Any) -> None:
            super().__init__(**data)
            self._check_invariants()

    def _check_invariants(self) -> None:
        if contains_forbidden_ti_keys(self.attributes):
            raise ValueError("Forbidden raw payload key found in TI attributes")
        if self.verdict != ObservableVerdictEnum.UNKNOWN:
            if not self.evidence or not str(self.evidence).strip():
                raise ValueError(
                    f"Non-unknown verdict '{self.verdict.value}' requires supporting evidence"
                )
            if self.lookup_status not in (
                ThreatIntelLookupStatusEnum.SUCCESS,
                ThreatIntelLookupStatusEnum.CACHE_HIT,
            ):
                raise ValueError(
                    f"Non-unknown verdict requires success or cache_hit status, got {self.lookup_status!r}"
                )


class EventEnrichmentResult(BaseModel):
    """
    Canonical output of the security enrichment stage for a single normalized event.
    """

    enrichment_status: EnrichmentStatusEnum = Field(
        description="Outcome status (enriched, enriched_partial, no_observables, skipped, failed)"
    )
    source_event_id: Optional[str] = Field(
        default=None, description="UUID of the evaluated normalized event"
    )
    ingestion_id: Optional[str] = Field(
        default=None, description="Ingestion UUID linking back to immutable raw evidence"
    )
    enriched_at: str = Field(
        description="ISO 8601 UTC timestamp when deterministic enrichment ran"
    )
    provider: str = Field(description="Primary enrichment provider identifier")
    provider_version: str = Field(description="Primary enrichment provider version")
    live_lookup_performed: bool = Field(
        default=False,
        description="Explicit indicator confirming whether any external TI lookup ran",
    )
    observable_count: int = Field(
        default=0, ge=0, description="Number of unique enriched observables produced"
    )
    observables: List[EnrichedObservable] = Field(
        default_factory=list,
        description="Deduplicated list of enriched observables with provenance",
    )
    warnings: List[ValidationIssue] = Field(
        default_factory=list,
        description="Non-blocking warnings (e.g., invalid observable values skipped)",
    )
    errors: List[ValidationIssue] = Field(
        default_factory=list,
        description="Blocking errors when enrichment status is 'failed'",
    )
