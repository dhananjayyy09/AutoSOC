"""
AutoSOC - Security Event Enrichment Contract & Schemas (Day 9 Reconciled)

Combines Pranjal's canonical observable contract (`app.threat_intelligence.schemas`)
with DJ's deterministic event-level network and indicator context into a single
persisted & API-serialized contract without mutating normalized events or raw payloads.
"""

from typing import Any, Dict, FrozenSet, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.threat_intelligence.schemas import (
    EnrichmentStatusEnum,
    ObservableClassificationEnum,
    ObservableTypeEnum,
    ObservableVerdictEnum,
)

ENRICHMENT_PIPELINE_VERSION = "0.3.0-day9"
MAX_PROVIDER_NAME_LENGTH = 64

FORBIDDEN_ENRICHMENT_KEYS: FrozenSet[str] = frozenset({"raw_payload", "raw_event"})


class NetworkEnrichmentContext(BaseModel):
    """Deterministic network and IP classification context derived from event endpoints."""

    model_config = ConfigDict(extra="forbid")

    is_internal_src: Optional[bool] = Field(
        default=None,
        description="True if source_ip is RFC 1918 private, ULA, loopback, or link-local",
    )
    is_internal_dst: Optional[bool] = Field(
        default=None,
        description="True if destination_ip is RFC 1918 private, ULA, loopback, or link-local",
    )
    is_external_to_internal: Optional[bool] = Field(
        default=None,
        description="True when source_ip is external and destination_ip is internal",
    )
    src_ip_version: Optional[int] = Field(
        default=None, description="IP version (4 or 6) when source_ip is valid"
    )
    dst_ip_version: Optional[int] = Field(
        default=None, description="IP version (4 or 6) when destination_ip is valid"
    )
    dst_port_well_known: Optional[bool] = Field(
        default=None, description="True if destination_port is in [0, 1023]"
    )
    geo: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional GeoIP summary when provided by an enrichment provider",
    )

    @field_validator("src_ip_version", "dst_ip_version")
    @classmethod
    def validate_ip_version(cls, value: Optional[int]) -> Optional[int]:
        if value is not None and value not in (4, 6):
            raise ValueError("IP version must be 4 or 6")
        return value


class IndicatorEnrichmentContext(BaseModel):
    """Deterministic structural attributes of domain, hash, and command indicators."""

    model_config = ConfigDict(extra="forbid")

    domain_length: Optional[int] = Field(default=None, ge=0)
    domain_tld: Optional[str] = Field(default=None, max_length=64)
    subdomain_count: Optional[int] = Field(default=None, ge=0)
    has_file_hash: bool = False
    file_hash_algorithm: Optional[str] = Field(default=None, max_length=32)
    has_command_line: bool = False
    command_line_length: Optional[int] = Field(default=None, ge=0)


class ThreatIntelContext(BaseModel):
    """Validated threat intelligence summary attached alongside observable context."""

    model_config = ConfigDict(extra="forbid")

    status: Optional[str] = Field(default=None, max_length=32)
    provider: Optional[str] = Field(default=None, max_length=MAX_PROVIDER_NAME_LENGTH)
    lookup_timestamp: Optional[str] = Field(default=None, max_length=64)
    cached: Optional[bool] = None
    live_lookup_performed: Optional[bool] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    evidence_summary: Optional[str] = Field(default=None, max_length=512)
    ip_score: Optional[int] = Field(default=None, ge=0, le=100)
    ip_categories: List[str] = Field(default_factory=list)
    domain_score: Optional[int] = Field(default=None, ge=0, le=100)
    hash_known_malware: Optional[bool] = None
    sources: List[str] = Field(default_factory=list)
    providers_queried: List[str] = Field(default_factory=list)
    cache_hits: int = Field(default=0, ge=0)
    live_lookups: int = Field(default=0, ge=0)
    max_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class CanonicalObservableProvenance(BaseModel):
    """Per-observable provenance aligned with app.threat_intelligence.schemas.EnrichmentProvenance."""

    model_config = ConfigDict(extra="forbid")

    source_event_id: Optional[str] = None
    ingestion_id: str = Field(min_length=1, max_length=36)
    source_fields: List[str] = Field(default_factory=list)
    original_values: List[str] = Field(default_factory=list)
    provider: str = Field(min_length=1, max_length=MAX_PROVIDER_NAME_LENGTH)
    provider_version: str = Field(min_length=1, max_length=32)
    method: str = Field(min_length=1, max_length=128)
    evidence: str = Field(min_length=1, max_length=512)
    live_lookup_performed: bool = False
    lookup_status: Optional[str] = Field(default=None, max_length=32)
    lookup_timestamp: Optional[str] = Field(default=None, max_length=64)


class CanonicalEnrichedObservable(BaseModel):
    """Canonical deduplicated observable with deterministic classification and provenance."""

    model_config = ConfigDict(extra="forbid")

    observable_type: ObservableTypeEnum
    normalized_value: str = Field(min_length=1, max_length=2048)
    original_value: str = Field(min_length=1, max_length=2048)
    classification: ObservableClassificationEnum
    verdict: ObservableVerdictEnum = ObservableVerdictEnum.UNKNOWN
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    lookup_status: Optional[str] = Field(default=None, max_length=32)
    lookup_timestamp: Optional[str] = Field(default=None, max_length=64)
    cached: Optional[bool] = None
    live_lookup_performed: Optional[bool] = None
    evidence_summary: Optional[str] = Field(default=None, max_length=512)
    references: List[Dict[str, Any]] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    provenance: CanonicalObservableProvenance


class EnrichmentProvenance(BaseModel):
    """Event-level traceability metadata recording enricher, version, and source IDs."""

    model_config = ConfigDict(extra="forbid")

    pipeline_version: str = Field(
        default=ENRICHMENT_PIPELINE_VERSION, min_length=1, max_length=64
    )
    provider: str = Field(min_length=1, max_length=MAX_PROVIDER_NAME_LENGTH)
    provider_version: str = Field(default="1.0.0", min_length=1, max_length=32)
    live_lookup_performed: bool = False
    enriched_fields: List[str] = Field(default_factory=list)
    source_event_id: str = Field(min_length=1, max_length=36)
    source_ingestion_id: str = Field(min_length=1, max_length=36)


class EventEnrichmentContextSections(BaseModel):
    """Deterministic event-level context sections preserved alongside observables."""

    model_config = ConfigDict(extra="forbid")

    network: NetworkEnrichmentContext = Field(default_factory=NetworkEnrichmentContext)
    indicators: IndicatorEnrichmentContext = Field(
        default_factory=IndicatorEnrichmentContext
    )
    threat_intel: Optional[ThreatIntelContext] = None


class NormalizedEventEnrichmentPayload(BaseModel):
    """
    Canonical enrichment payload stored separately in `event_enrichments.enrichment_data`.
    Contains both extracted `observables[]` and event-level `context` (`network`, `indicators`).
    """

    model_config = ConfigDict(extra="forbid")

    observable_count: int = Field(default=0, ge=0)
    observables: List[CanonicalEnrichedObservable] = Field(default_factory=list)
    context: EventEnrichmentContextSections = Field(
        default_factory=EventEnrichmentContextSections
    )


class EnrichmentResult(BaseModel):
    """Standardized output contract returned by EventEnricherProtocol implementations."""

    model_config = ConfigDict(extra="forbid")

    status: EnrichmentStatusEnum
    provider: str = Field(min_length=1, max_length=MAX_PROVIDER_NAME_LENGTH)
    provider_version: str = Field(default="1.0.0", min_length=1, max_length=32)
    live_lookup_performed: bool = False
    provenance: EnrichmentProvenance
    enrichment_data: Optional[NormalizedEventEnrichmentPayload] = None
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


def contains_forbidden_raw_keys(obj: Any) -> bool:
    """Recursively ensure raw payload keys never appear inside enrichment data."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k) in FORBIDDEN_ENRICHMENT_KEYS or contains_forbidden_raw_keys(v):
                return True
    elif isinstance(obj, list):
        return any(contains_forbidden_raw_keys(item) for item in obj)
    return False
