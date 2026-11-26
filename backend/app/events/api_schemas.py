"""
AutoSOC - API Request and Response Schemas for Security Event Ingestion

Extends the authoritative IngestionEnvelope contract (app.events.schemas) with
boundary format validation and defines safe response models for ingestion and
bounded retrieval endpoints.
"""

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

from app.events.schemas import (
    EventCategoryEnum,
    IngestionEnvelope,
    NormalizationStatusEnum,
    SourceTypeEnum,
)

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


class EventSortFieldEnum(str, Enum):
    """Approved sortable fields on normalized_events."""

    CREATED_AT = "created_at"
    TIMESTAMP = "timestamp"
    SEVERITY = "severity"
    SOURCE_TYPE = "source_type"
    NORMALIZATION_STATUS = "normalization_status"
    EVENT_CATEGORY = "event_category"
    EVENT_TYPE = "event_type"


class SortOrderEnum(str, Enum):
    """Approved sort directions."""

    DESC = "desc"
    ASC = "asc"


def _normalize_query_utc_iso(value: str, field_name: str) -> str:
    """Validate an ISO 8601 timestamp with timezone and normalize to UTC ms format."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty ISO 8601 timestamp")
    raw = value.strip()
    normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a UTC or timezone offset")
    utc_dt = parsed.astimezone(timezone.utc)
    ms = utc_dt.microsecond // 1000
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"


class NormalizedEventQueryParams(BaseModel):
    """Validated query parameters for filtering, searching, sorting, and paginating normalized events."""

    limit: int = Field(default=20, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=100_000)
    source_type: Optional[SourceTypeEnum] = None
    normalization_status: Optional[NormalizationStatusEnum] = None
    event_category: Optional[EventCategoryEnum] = None
    event_type: Optional[str] = Field(default=None, max_length=64)
    severity: Optional[int] = Field(default=None, ge=1, le=5)
    min_severity: Optional[int] = Field(default=None, ge=1, le=5)
    max_severity: Optional[int] = Field(default=None, ge=1, le=5)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    search: Optional[str] = Field(default=None, max_length=128)
    sort_by: EventSortFieldEnum = EventSortFieldEnum.CREATED_AT
    sort_order: SortOrderEnum = SortOrderEnum.DESC

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("event_type must not be empty whitespace")
        return stripped

    @field_validator("search")
    @classmethod
    def normalize_search(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    @field_validator("start_time")
    @classmethod
    def validate_start_time(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return _normalize_query_utc_iso(value, "start_time")

    @field_validator("end_time")
    @classmethod
    def validate_end_time(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return _normalize_query_utc_iso(value, "end_time")

    @model_validator(mode="after")
    def validate_ranges(self) -> "NormalizedEventQueryParams":
        if (
            self.min_severity is not None
            and self.max_severity is not None
            and self.min_severity > self.max_severity
        ):
            raise ValueError("min_severity must be less than or equal to max_severity")
        if (
            self.start_time is not None
            and self.end_time is not None
            and self.start_time > self.end_time
        ):
            raise ValueError("start_time must be less than or equal to end_time")
        return self


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


def build_payload_preview(raw_payload: str, max_chars: int = PREVIEW_MAX_CHARS) -> str:
    """Return a bounded preview of raw_payload for safe list retrieval."""
    if len(raw_payload) <= max_chars:
        return raw_payload
    return raw_payload[:max_chars] + "..."
