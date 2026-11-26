"""
AutoSOC - Security Event Enrichment Contract & Schemas (Day 9)

Defines the canonical, validated schemas for deterministic event enrichment
without mutating normalized event columns or raw ingestion payloads.
"""

from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

ENRICHMENT_PIPELINE_VERSION = "0.3.0-day9"
MAX_PROVIDER_NAME_LENGTH = 64

FORBIDDEN_ENRICHMENT_KEYS: FrozenSet[str] = frozenset({"raw_payload", "raw_event"})


class EnrichmentStatusEnum(str, Enum):
    """Lifecycle outcomes for deterministic normalized-event enrichment."""

    ENRICHED = "enriched"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"


class NetworkEnrichmentContext(BaseModel):
    """Deterministic network and IP classification context derived from event endpoints."""

    model_config = ConfigDict(extra="forbid")

    is_internal_src: Optional[bool] = Field(
        default=None,
        description="True if source_ip is RFC 1918 private, loopback, or link-local",
    )
    is_internal_dst: Optional[bool] = Field(
        default=None,
        description="True if destination_ip is RFC 1918 private, loopback, or link-local",
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
    """Validated threat intelligence placeholder/provider context (detection-neutral)."""

    model_config = ConfigDict(extra="forbid")

    ip_score: Optional[int] = Field(default=None, ge=0, le=100)
    ip_categories: List[str] = Field(default_factory=list)
    domain_score: Optional[int] = Field(default=None, ge=0, le=100)
    hash_known_malware: Optional[bool] = None
    sources: List[str] = Field(default_factory=list)


class EnrichmentProvenance(BaseModel):
    """Traceability metadata recording which enricher/version produced an enrichment."""

    model_config = ConfigDict(extra="forbid")

    pipeline_version: str = Field(default=ENRICHMENT_PIPELINE_VERSION, min_length=1, max_length=64)
    provider: str = Field(min_length=1, max_length=MAX_PROVIDER_NAME_LENGTH)
    provider_version: str = Field(default="1.0.0", min_length=1, max_length=32)
    enriched_fields: List[str] = Field(default_factory=list)
    source_event_id: str = Field(min_length=1, max_length=36)
    source_ingestion_id: str = Field(min_length=1, max_length=36)


class NormalizedEventEnrichmentPayload(BaseModel):
    """Validated enrichment data structure stored separately from normalized event columns."""

    model_config = ConfigDict(extra="forbid")

    network: NetworkEnrichmentContext = Field(default_factory=NetworkEnrichmentContext)
    indicators: IndicatorEnrichmentContext = Field(default_factory=IndicatorEnrichmentContext)
    threat_intel: Optional[ThreatIntelContext] = None


class EnrichmentResult(BaseModel):
    """Standardized output contract returned by EventEnricherProtocol implementations."""

    model_config = ConfigDict(extra="forbid")

    status: EnrichmentStatusEnum
    provider: str = Field(min_length=1, max_length=MAX_PROVIDER_NAME_LENGTH)
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
