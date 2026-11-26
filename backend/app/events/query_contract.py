"""
AutoSOC - Normalized Event Explorer Query Contract (Day 8)

Defines strict, deterministic query parameter schemas, validation rules,
allowlisted searchable/sortable fields, and pagination bounds for the
Normalized Event Explorer API (`GET /api/v1/events/normalized`).

Shared contract between DJ's backend repository/endpoint and Shreyash's
frontend query controls. Does not execute database queries or expose raw_payload.
"""

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from app.events.schemas import (
    PYDANTIC_V2,
    BaseModel,
    EventCategoryEnum,
    Field,
    NormalizationStatusEnum,
    SourceTypeEnum,
)
from app.events.validation import ValidationErrorCategory, ValidationIssue

if PYDANTIC_V2:
    from pydantic import model_validator

DEFAULT_QUERY_LIMIT = 20
MAX_QUERY_LIMIT = 100
DEFAULT_QUERY_OFFSET = 0
MAX_QUERY_OFFSET = 10_000
MAX_SEARCH_LENGTH = 128
MAX_EVENT_TYPE_LENGTH = 64

_EVENT_TYPE_PATTERN = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")


class NormalizedEventSortField(str, Enum):
    """Allowlisted sortable columns on `normalized_events`."""

    CREATED_AT = "created_at"
    TIMESTAMP = "timestamp"
    SEVERITY = "severity"
    SOURCE_TYPE = "source_type"
    EVENT_CATEGORY = "event_category"
    NORMALIZATION_STATUS = "normalization_status"


class SortOrderEnum(str, Enum):
    """Deterministic sort direction."""

    ASC = "asc"
    DESC = "desc"


# Strict allowlist of persisted NormalizedEvent columns eligible for `search`.
# `raw_payload` is intentionally excluded (not in normalized_events and never
# searchable via the normalized list API).
SEARCHABLE_NORMALIZED_EVENT_FIELDS: Tuple[str, ...] = (
    "event_id",
    "ingestion_id",
    "sensor_id",
    "event_type",
    "host",
    "user_name",
    "source_ip",
    "destination_ip",
    "process",
    "domain",
    "file_hash",
    "command_line",
)

# Maps API sort_by enum values to persisted NormalizedEvent ORM attribute names.
SORT_FIELD_TO_ORM_COLUMN: Dict[NormalizedEventSortField, str] = {
    NormalizedEventSortField.CREATED_AT: "created_at",
    NormalizedEventSortField.TIMESTAMP: "event_timestamp",
    NormalizedEventSortField.SEVERITY: "severity",
    NormalizedEventSortField.SOURCE_TYPE: "source_type",
    NormalizedEventSortField.EVENT_CATEGORY: "event_category",
    NormalizedEventSortField.NORMALIZATION_STATUS: "normalization_status",
}

EXPLICITLY_FORBIDDEN_SEARCH_FIELDS: FrozenSet[str] = frozenset(
    {"raw_payload", "raw_event", "metadata", "normalization_errors", "normalization_warnings"}
)


def _clean_optional_str(value: Any, field_name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    stripped = value.strip()
    return stripped if stripped else None


def _parse_utc_query_timestamp(value: Any, field_name: str) -> Optional[str]:
    """
    Validate an ISO 8601 timestamp with explicit timezone offset and normalize
    it to canonical millisecond UTC ISO 8601 (`YYYY-MM-DDTHH:MM:SS.sssZ`).
    Naive timestamps without timezone offsets are rejected.
    """
    cleaned = _clean_optional_str(value, field_name)
    if cleaned is None:
        return None

    normalized = cleaned[:-1] + "+00:00" if cleaned.endswith("Z") else cleaned
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid ISO 8601 timestamp") from exc

    if dt.tzinfo is None:
        raise ValueError(f"{field_name} must include 'Z' or an explicit UTC timezone offset")

    utc_dt = dt.astimezone(timezone.utc)
    ms = utc_dt.microsecond // 1000
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"


def _validate_int_bound(
    value: Any, field_name: str, *, min_val: int, max_val: int
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if value < min_val or value > max_val:
        raise ValueError(f"{field_name} must be between {min_val} and {max_val}")
    return value


def _validate_enum_field(value: Any, enum_cls: Any, field_name: str) -> Any:
    if value is None:
        return None
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            return enum_cls(cleaned)
        except ValueError as exc:
            allowed = ", ".join(m.value for m in enum_cls)
            raise ValueError(
                f"Invalid {field_name} '{cleaned}'; allowed values: {allowed}"
            ) from exc
    raise ValueError(f"{field_name} must be a valid string enum value")


def escape_like_pattern(search_term: str) -> str:
    """
    Escape SQL LIKE/ILIKE wildcard characters (`%`, `_`, `\\`) so user search
    input is matched literally inside parameterized queries.
    """
    return (
        search_term.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


class NormalizedEventQueryParams(BaseModel):
    """
    Validated query contract for `GET /api/v1/events/normalized`.
    """

    source_type: Optional[SourceTypeEnum] = Field(
        default=None, description="Filter by telemetry source type"
    )
    normalization_status: Optional[NormalizationStatusEnum] = Field(
        default=None, description="Filter by normalization lifecycle status"
    )
    event_category: Optional[EventCategoryEnum] = Field(
        default=None, description="Filter by coarse event category"
    )
    event_type: Optional[str] = Field(
        default=None, description="Filter by normalized dot-notation event_type"
    )
    severity: Optional[int] = Field(
        default=None, ge=1, le=5, description="Filter by normalized severity (1-5)"
    )
    start_time: Optional[str] = Field(
        default=None, description="Inclusive lower UTC ISO 8601 bound on event_timestamp"
    )
    end_time: Optional[str] = Field(
        default=None, description="Inclusive upper UTC ISO 8601 bound on event_timestamp"
    )
    search: Optional[str] = Field(
        default=None, description="Case-insensitive literal substring filter over approved fields"
    )
    sort_by: NormalizedEventSortField = Field(
        default=NormalizedEventSortField.CREATED_AT,
        description="Allowlisted sort column",
    )
    sort_order: SortOrderEnum = Field(
        default=SortOrderEnum.DESC, description="Sort direction ('asc' or 'desc')"
    )
    limit: int = Field(
        default=DEFAULT_QUERY_LIMIT,
        ge=1,
        le=MAX_QUERY_LIMIT,
        description="Maximum items per page (1-100)",
    )
    offset: int = Field(
        default=DEFAULT_QUERY_OFFSET,
        ge=0,
        le=MAX_QUERY_OFFSET,
        description="Zero-based pagination offset (0-10000)",
    )

    def _apply_and_validate(self) -> None:
        self.source_type = _validate_enum_field(
            self.source_type, SourceTypeEnum, "source_type"
        )
        self.normalization_status = _validate_enum_field(
            self.normalization_status, NormalizationStatusEnum, "normalization_status"
        )
        self.event_category = _validate_enum_field(
            self.event_category, EventCategoryEnum, "event_category"
        )

        cleaned_type = _clean_optional_str(self.event_type, "event_type")
        if cleaned_type is not None:
            lowered_type = cleaned_type.lower()
            if len(lowered_type) > MAX_EVENT_TYPE_LENGTH:
                raise ValueError(
                    f"event_type must not exceed {MAX_EVENT_TYPE_LENGTH} characters"
                )
            if not _EVENT_TYPE_PATTERN.match(lowered_type):
                raise ValueError(
                    "event_type must use lowercase alphanumeric dot-notation (e.g. 'alert.ids')"
                )
            self.event_type = lowered_type
        else:
            self.event_type = None

        if self.severity is not None:
            self.severity = _validate_int_bound(
                self.severity, "severity", min_val=1, max_val=5
            )

        self.start_time = _parse_utc_query_timestamp(self.start_time, "start_time")
        self.end_time = _parse_utc_query_timestamp(self.end_time, "end_time")
        if self.start_time is not None and self.end_time is not None:
            if self.start_time > self.end_time:
                raise ValueError("start_time must be less than or equal to end_time")

        cleaned_search = _clean_optional_str(self.search, "search")
        if cleaned_search is not None:
            if len(cleaned_search) > MAX_SEARCH_LENGTH:
                raise ValueError(
                    f"search must not exceed {MAX_SEARCH_LENGTH} characters"
                )
            self.search = cleaned_search
        else:
            self.search = None

        sort_by_val = _validate_enum_field(
            self.sort_by, NormalizedEventSortField, "sort_by"
        )
        self.sort_by = (
            sort_by_val
            if sort_by_val is not None
            else NormalizedEventSortField.CREATED_AT
        )

        sort_order_val = (
            self.sort_order.lower()
            if isinstance(self.sort_order, str)
            else self.sort_order
        )
        validated_order = _validate_enum_field(
            sort_order_val, SortOrderEnum, "sort_order"
        )
        self.sort_order = (
            validated_order if validated_order is not None else SortOrderEnum.DESC
        )

        self.limit = _validate_int_bound(
            self.limit, "limit", min_val=1, max_val=MAX_QUERY_LIMIT
        )
        self.offset = _validate_int_bound(
            self.offset, "offset", min_val=0, max_val=MAX_QUERY_OFFSET
        )

    if PYDANTIC_V2:

        @model_validator(mode="before")
        @classmethod
        def _pre_normalize_inputs(cls, data: Any) -> Any:
            if not isinstance(data, dict):
                return data
            cleaned = dict(data)
            for int_field in ("severity", "limit", "offset"):
                if int_field in cleaned and isinstance(cleaned[int_field], bool):
                    raise ValueError(f"{int_field} must be an integer")
            for opt_str_field in (
                "source_type",
                "normalization_status",
                "event_category",
                "event_type",
                "start_time",
                "end_time",
                "search",
            ):
                val = cleaned.get(opt_str_field)
                if isinstance(val, str) and not val.strip():
                    cleaned[opt_str_field] = None
            return cleaned

        @model_validator(mode="after")
        def _pydantic_validate(self) -> "NormalizedEventQueryParams":
            self._apply_and_validate()
            return self

    else:

        def __init__(self, **data: Any) -> None:
            # Allow string values for enums in fallback before _apply_and_validate runs
            raw_overrides: Dict[str, Any] = {}
            for enum_key in (
                "source_type",
                "normalization_status",
                "event_category",
                "sort_by",
                "sort_order",
            ):
                if enum_key in data:
                    raw_overrides[enum_key] = data.pop(enum_key)
            super().__init__(**data)
            for k, v in raw_overrides.items():
                setattr(self, k, v)
            self._apply_and_validate()


class QueryValidationResult(BaseModel):
    """Structured query validation outcome with sanitized error reporting."""

    valid: bool = Field(description="True if query parameters are valid")
    params: Optional[NormalizedEventQueryParams] = Field(
        default=None, description="Normalized query parameters when valid"
    )
    errors: List[ValidationIssue] = Field(
        default_factory=list, description="Structured validation errors when invalid"
    )


def validate_normalized_event_query(
    raw_params: Optional[Dict[str, Any]] = None,
) -> QueryValidationResult:
    """
    Validate raw query parameters against NormalizedEventQueryParams and return
    a structured QueryValidationResult suitable for API 422 responses.
    """
    payload = {} if raw_params is None else raw_params
    if not isinstance(payload, dict):
        return QueryValidationResult(
            valid=False,
            errors=[
                ValidationIssue(
                    category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                    field="query",
                    message="Query parameters must be a key-value object",
                    severity="error",
                )
            ],
        )

    allowed_keys = set(NormalizedEventQueryParams.__annotations__.keys())
    unknown_keys = sorted(k for k in payload.keys() if k not in allowed_keys)
    if unknown_keys:
        return QueryValidationResult(
            valid=False,
            errors=[
                ValidationIssue(
                    category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                    field=key,
                    message=f"Unsupported query parameter '{key}'",
                    severity="error",
                )
                for key in unknown_keys
            ],
        )

    try:
        validated = NormalizedEventQueryParams(**payload)
        return QueryValidationResult(valid=True, params=validated, errors=[])
    except Exception as exc:
        return QueryValidationResult(
            valid=False,
            errors=[
                ValidationIssue(
                    category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                    field="query",
                    message=str(exc),
                    severity="error",
                )
            ],
        )
