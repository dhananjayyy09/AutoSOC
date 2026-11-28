"""
AutoSOC - Canonical Security Enrichment Contract (Day 9)

Single source of truth for security enrichment statuses, observable types,
factual classifications, provenance, and structured enrichment results.
Reuses `BaseModel` and `Field` from `app.events.schemas` and `ValidationIssue`
from `app.events.validation` without duplicating schema definitions.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from app.events.schemas import BaseModel, Field
from app.events.validation import ValidationIssue


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
    Conservative, evidence-driven reputation/threat verdict for an observable.
    `unknown` means no reliable reputation conclusion is available.
    Explicit benign/suspicious/malicious verdicts are represented only when
    supplied by a validated threat-intelligence provider contract.
    """

    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


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
        description="Threat verdict ('unknown' for Day 9 local enrichment)",
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Deterministic structural attributes (e.g., ip_version, is_internal, tld, scheme, algorithm)",
    )
    provenance: EnrichmentProvenance = Field(
        description="Full provenance chain linking back to source event and fields"
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
