"""
AutoSOC - API Request and Response Schemas for Security Event Ingestion

Extends the authoritative IngestionEnvelope contract (app.events.schemas) with
boundary format validation and defines safe response models for ingestion and
bounded retrieval endpoints.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.events.enrichment_contract import (
    EnrichmentProvenance,
    EnrichmentStatusEnum,
    MAX_PROVIDER_NAME_LENGTH,
    NormalizedEventEnrichmentPayload,
)
from app.events.query_contract import (
    DEFAULT_QUERY_LIMIT,
    DEFAULT_QUERY_OFFSET,
    MAX_EVENT_TYPE_LENGTH,
    MAX_QUERY_LIMIT,
    MAX_QUERY_OFFSET,
    MAX_SEARCH_LENGTH,
    NormalizedEventQueryParams,
    NormalizedEventSortField,
    SortOrderEnum,
)
from app.events.schemas import IngestionEnvelope, SourceTypeEnum

EventSortFieldEnum = NormalizedEventSortField

MAX_RAW_PAYLOAD_BYTES = 65_536  # 64 KiB per Security Data Contract §3 Stage 1
RAW_HASH_PATTERN = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
PREVIEW_MAX_CHARS = 256


class EventIngestionRequest(IngestionEnvelope):
    """
    HTTP ingestion payload validated against the authoritative IngestionEnvelope
    contract with strict field-format checks. Does not invent a separate contract.
    """

    @field_validator("ingestion_id")
    @classmethod
    def validate_ingestion_id(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("ingestion_id must be a non-empty UUID string")
        try:
            UUID(value)
        except ValueError as exc:
            raise ValueError("ingestion_id must be a valid UUID") from exc
        return value

    @field_validator("sensor_id")
    @classmethod
    def validate_sensor_id(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("sensor_id must not be empty")
        if len(stripped) > 255:
            raise ValueError("sensor_id must not exceed 255 characters")
        return stripped

    @field_validator("ingest_time")
    @classmethod
    def validate_ingest_time(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("ingest_time must be a non-empty ISO 8601 timestamp")
        try:
            normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError("ingest_time must be a valid ISO 8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("ingest_time must include UTC/timezone offset")
        return value

    @field_validator("raw_hash")
    @classmethod
    def validate_raw_hash(cls, value: str) -> str:
        if not RAW_HASH_PATTERN.match(value):
            raise ValueError("raw_hash must match format 'sha256:<64 hex chars>'")
        return value.lower()

    @field_validator("raw_payload")
    @classmethod
    def validate_raw_payload(cls, value: str) -> str:
        if not value:
            raise ValueError("raw_payload must not be empty")
        if len(value.encode("utf-8")) > MAX_RAW_PAYLOAD_BYTES:
            # Never echo raw_payload content in validation error messages
            raise ValueError(
                f"raw_payload exceeds maximum size of {MAX_RAW_PAYLOAD_BYTES} bytes"
            )
        return value


class EventIngestionResponse(BaseModel):
    """Stable acknowledgement returned upon persisting a raw security-event envelope."""

    ingestion_id: str = Field(description="Unique delivery attempt UUID from envelope")
    event_id: Optional[str] = Field(
        default=None,
        description="Normalized event UUID if deterministic normalization succeeded",
    )
    source_type: SourceTypeEnum = Field(description="Validated telemetry source type")
    status: str = Field(description="Processing disposition status (accepted or accepted_with_warnings)")
    normalization_status: Optional[str] = Field(
        default=None,
        description="Normalization outcome (normalized, normalized_with_warnings, failed, unsupported)",
    )
    enrichment_status: Optional[str] = Field(
        default=None,
        description="Enrichment outcome (enriched, partial, skipped, failed) when normalization produced an event",
    )
    possible_duplicate: bool = Field(
        description="True if an identical raw_hash was previously ingested"
    )
    received_at: str = Field(description="ISO 8601 UTC timestamp of persistence")
    warnings: List[str] = Field(
        default_factory=list,
        description="Non-blocking validation warnings (never contains raw payloads)",
    )


class IngestedEventSummary(BaseModel):
    """
    Safe, bounded representation of a persisted raw event envelope for retrieval.
    Avoids returning unbounded raw_payload strings in list responses.
    """

    ingestion_id: str
    source_type: SourceTypeEnum
    sensor_id: str
    ingest_time: str
    raw_hash: str
    payload_size_bytes: int
    raw_payload_preview: str = Field(
        description="Bounded preview of raw_payload (max 256 chars + ellipsis)"
    )
    possible_duplicate: bool
    status: str
    received_at: str


class IngestedEventListResponse(BaseModel):
    """Paginated/bounded list of recently ingested raw event envelopes."""

    items: List[IngestedEventSummary]
    count: int
    limit: int


class NormalizedEventResponse(BaseModel):
    """Safe API representation of a normalized security event (omits raw_payload)."""

    event_id: Optional[str] = None
    ingestion_id: str
    raw_envelope_id: int
    timestamp: Optional[str] = None
    source_type: SourceTypeEnum
    sensor_id: str
    event_category: Optional[str] = None
    event_type: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    process: Optional[str] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    command_line: Optional[str] = None
    severity: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    normalization_status: str
    normalization_errors: List[str] = Field(default_factory=list)
    normalization_warnings: List[str] = Field(default_factory=list)
    created_at: str


class NormalizedEventListResponse(BaseModel):
    """Bounded, paginated list of normalized security events."""

    items: List[NormalizedEventResponse]
    count: int
    total: int = Field(default=0, ge=0, description="Total matching events before pagination")
    limit: int
    offset: int = Field(default=0, ge=0, description="Zero-based pagination offset")
    has_more: bool = Field(
        default=False, description="True if additional matching events exist beyond offset + count"
    )


class EventEnrichmentQueryParams(BaseModel):
    """Validated query parameters for listing persisted event enrichments."""

    limit: int = Field(default=DEFAULT_QUERY_LIMIT, ge=1, le=MAX_QUERY_LIMIT)
    offset: int = Field(default=DEFAULT_QUERY_OFFSET, ge=0, le=MAX_QUERY_OFFSET)
    enrichment_status: Optional[EnrichmentStatusEnum] = None
    provider: Optional[str] = Field(default=None, max_length=MAX_PROVIDER_NAME_LENGTH)
    sort_order: SortOrderEnum = SortOrderEnum.DESC

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            return None
        if not re.match(r"^[a-zA-Z0-9_.-]{1,64}$", stripped):
            raise ValueError(
                "provider must contain only alphanumeric, '.', '_', or '-' characters"
            )
        return stripped


class EventEnrichmentResponse(BaseModel):
    """Safe API representation of separate event enrichment context (omits raw payloads)."""

    enrichment_id: str
    event_id: str
    ingestion_id: str
    provider: str
    enrichment_status: EnrichmentStatusEnum
    enrichment_data: Optional[NormalizedEventEnrichmentPayload] = None
    provenance: EnrichmentProvenance
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    attempt_count: int = Field(ge=1)
    enriched_at: Optional[str] = None
    created_at: str
    updated_at: str


class EventEnrichmentListResponse(BaseModel):
    """Bounded, paginated list of event enrichment records."""

    items: List[EventEnrichmentResponse]
    count: int
    total: int = Field(default=0, ge=0)
    limit: int
    offset: int = Field(default=0, ge=0)
    has_more: bool = Field(default=False)


def build_payload_preview(raw_payload: str, max_chars: int = PREVIEW_MAX_CHARS) -> str:
    """Return a bounded preview of raw_payload for safe list retrieval."""
    if len(raw_payload) <= max_chars:
        return raw_payload
    return raw_payload[:max_chars] + "..."
