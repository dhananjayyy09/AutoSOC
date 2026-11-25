"""
AutoSOC - Security Event Ingestion Envelope Validation Component

Validates incoming IngestionEnvelope payloads against the Day 5 schemas and
docs/security/security-data-contract.md (Stage 1 & Stage 4 rules).
Produces structured, sanitized validation results without executing parsing,
normalization, detection, or database persistence.
"""

from datetime import datetime, timezone, timedelta
from enum import Enum
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Protocol, Set, Tuple, runtime_checkable
import uuid

from app.events.schemas import (
    BaseModel,
    EventMetadata,
    Field,
    IngestionEnvelope,
    SourceTypeEnum,
)

MAX_RAW_PAYLOAD_BYTES = 65_536  # 64 KiB per security-event-model.md §4.17
MAX_SENSOR_ID_LENGTH = 255
DEFAULT_FUTURE_SKEW_SECONDS = 300  # 5 minutes per security-data-contract.md §4B

_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

# Source types that have defined canonical ingestion formats vs. unsupported
UNSUPPORTED_SOURCE_TYPES: Set[SourceTypeEnum] = {SourceTypeEnum.CUSTOM}


class IngestionDisposition(str, Enum):
    """Deterministic acceptance outcome for an incoming ingestion envelope."""
    ACCEPTED = "accepted"
    ACCEPTED_WITH_WARNINGS = "accepted_with_warnings"
    REJECTED = "rejected"
    UNSUPPORTED = "unsupported"


class ValidationErrorCategory(str, Enum):
    """Structured error/warning categories for ingestion validation."""
    MISSING_REQUIRED_FIELD = "missing_required_field"
    INVALID_SCHEMA_TYPE = "invalid_schema_type"
    INVALID_IDENTIFIER = "invalid_identifier"
    INVALID_TIMESTAMP = "invalid_timestamp"
    UNSUPPORTED_SOURCE_TYPE = "unsupported_source_type"
    MALFORMED_PAYLOAD = "malformed_payload"
    HASH_MISMATCH = "hash_mismatch"
    INVALID_METADATA = "invalid_metadata"
    DUPLICATE_EVENT = "duplicate_event"
    PAYLOAD_TRUNCATED = "payload_truncated"


class ValidationIssue(BaseModel):
    """Sanitized validation error or warning entry (never embeds raw payload)."""
    category: ValidationErrorCategory = Field(description="Structured issue category")
    field: str = Field(description="Envelope or metadata field associated with the issue")
    message: str = Field(description="Sanitized human-readable diagnostic message")
    severity: str = Field(default="error", description="'error' or 'warning'")


class IngestionValidationResult(BaseModel):
    """Structured outcome returned by the ingestion envelope validator."""
    valid: bool = Field(description="True if accepted or accepted_with_warnings; False otherwise")
    disposition: IngestionDisposition = Field(description="Deterministic disposition")
    envelope: Optional[IngestionEnvelope] = Field(default=None, description="Validated IngestionEnvelope when valid")
    ingestion_id: Optional[str] = Field(default=None, description="Sanitized ingestion_id if valid UUID v4")
    raw_hash: Optional[str] = Field(default=None, description="Validated sha256 digest if well-formed")
    is_duplicate: bool = Field(default=False, description="True if duplicate raw_hash or ingestion_id was observed")
    duplicate_type: Optional[str] = Field(default=None, description="'raw_hash', 'ingestion_id', or None")
    raw_truncated: bool = Field(default=False, description="True if raw_payload exceeded 64 KiB limit")
    errors: List[ValidationIssue] = Field(default_factory=list, description="Blocking validation errors")
    warnings: List[ValidationIssue] = Field(default_factory=list, description="Non-blocking validation warnings")


@runtime_checkable
class DuplicateTrackerProtocol(Protocol):
    """Interface for tracking seen raw_hash and ingestion_id values (e.g. Redis in Phase 2)."""

    async def check_and_record(
        self, ingestion_id: str, raw_hash: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Checks if ingestion_id or raw_hash was previously seen and records new entries.
        Returns: (is_duplicate: bool, duplicate_type: Optional[str])
        """
        ...


class InMemoryDuplicateTracker:
    """
    Deterministic in-memory duplicate tracker for contract testing and local verification.
    Follows docs/security/security-data-contract.md §7: duplicates are flagged, never dropped.
    """

    def __init__(self) -> None:
        self._seen_ingestion_ids: Set[str] = set()
        self._seen_raw_hashes: Set[str] = set()

    async def check_and_record(
        self, ingestion_id: str, raw_hash: str
    ) -> Tuple[bool, Optional[str]]:
        if ingestion_id in self._seen_ingestion_ids:
            self._seen_raw_hashes.add(raw_hash)
            return True, "ingestion_id"

        if raw_hash in self._seen_raw_hashes:
            self._seen_ingestion_ids.add(ingestion_id)
            return True, "raw_hash"

        self._seen_ingestion_ids.add(ingestion_id)
        self._seen_raw_hashes.add(raw_hash)
        return False, None


def compute_raw_hash(raw_payload: str) -> str:
    """Compute canonical sha256:<hex> digest of raw_payload UTF-8 bytes."""
    digest = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _is_valid_uuid_v4(value: Any) -> bool:
    """Return True if value is a string representing a valid RFC 4122 UUID v4."""
    if not isinstance(value, str):
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return parsed.version == 4 and parsed.variant == uuid.RFC_4122


def _parse_iso8601_utc(value: Any) -> Optional[datetime]:
    """Parse an explicit UTC ISO 8601 timestamp string, returning None if invalid or non-UTC."""
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    elif not (normalized.endswith("+00:00") or normalized.endswith("-00:00")):
        return None
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None or dt.utcoffset() != timedelta(0):
        return None
    return dt


def _check_payload_structure(
    source_type: SourceTypeEnum, raw_payload: str
) -> Optional[ValidationIssue]:
    """
    Lightweight structural sanity check per source_type without parsing fields.
    Never includes raw_payload content in the returned message.
    """
    stripped = raw_payload.strip()
    if source_type == SourceTypeEnum.SURICATA:
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            return ValidationIssue(
                category=ValidationErrorCategory.MALFORMED_PAYLOAD,
                field="raw_payload",
                message="raw_payload for source_type 'suricata' must be valid JSON",
                severity="error",
            )
        if not isinstance(parsed, dict):
            return ValidationIssue(
                category=ValidationErrorCategory.MALFORMED_PAYLOAD,
                field="raw_payload",
                message="raw_payload for source_type 'suricata' must be a JSON object",
                severity="error",
            )
    elif source_type == SourceTypeEnum.SYSMON:
        if not (stripped.startswith("<") and stripped.endswith(">")):
            return ValidationIssue(
                category=ValidationErrorCategory.MALFORMED_PAYLOAD,
                field="raw_payload",
                message="raw_payload for source_type 'sysmon' must be XML-formatted",
                severity="error",
            )
    elif source_type == SourceTypeEnum.ZEEK:
        if stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                return ValidationIssue(
                    category=ValidationErrorCategory.MALFORMED_PAYLOAD,
                    field="raw_payload",
                    message="raw_payload JSON for source_type 'zeek' is malformed",
                    severity="error",
                )
            if not isinstance(parsed, dict):
                return ValidationIssue(
                    category=ValidationErrorCategory.MALFORMED_PAYLOAD,
                    field="raw_payload",
                    message="raw_payload JSON for source_type 'zeek' must be a JSON object",
                    severity="error",
                )
    return None


def validate_event_metadata(metadata: Any) -> List[ValidationIssue]:
    """
    Validate EventMetadata structure and reserved field constraints without leaking values.
    """
    issues: List[ValidationIssue] = []
    if not isinstance(metadata, dict):
        issues.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_METADATA,
                field="metadata",
                message="metadata must be a JSON object",
                severity="error",
            )
        )
        return issues

    required_meta = ("ingest_time", "pipeline_version", "raw_hash")
    for key in required_meta:
        val = metadata.get(key)
        if val is None or (isinstance(val, str) and not val.strip()):
            issues.append(
                ValidationIssue(
                    category=ValidationErrorCategory.INVALID_METADATA,
                    field=f"metadata.{key}",
                    message=f"Required metadata field '{key}' is missing or empty",
                    severity="error",
                )
            )

    if "ingest_time" in metadata and metadata["ingest_time"] is not None:
        if _parse_iso8601_utc(metadata["ingest_time"]) is None:
            issues.append(
                ValidationIssue(
                    category=ValidationErrorCategory.INVALID_TIMESTAMP,
                    field="metadata.ingest_time",
                    message="metadata.ingest_time must be a valid ISO 8601 UTC timestamp",
                    severity="error",
                )
            )

    if "raw_hash" in metadata and metadata["raw_hash"] is not None:
        raw_hash = metadata["raw_hash"]
        if not isinstance(raw_hash, str) or not _SHA256_PATTERN.match(raw_hash):
            issues.append(
                ValidationIssue(
                    category=ValidationErrorCategory.INVALID_IDENTIFIER,
                    field="metadata.raw_hash",
                    message="metadata.raw_hash must match 'sha256:<64-lowercase-hex>'",
                    severity="error",
                )
            )

    for bool_key in ("raw_truncated", "possible_duplicate", "timestamp_future", "timestamp_stale"):
        if bool_key in metadata and metadata[bool_key] is not None:
            if not isinstance(metadata[bool_key], bool):
                issues.append(
                    ValidationIssue(
                        category=ValidationErrorCategory.INVALID_METADATA,
                        field=f"metadata.{bool_key}",
                        message=f"metadata.{bool_key} must be a boolean",
                        severity="error",
                    )
                )

    for list_key in ("mitre_techniques", "tags"):
        if list_key in metadata and metadata[list_key] is not None:
            val = metadata[list_key]
            if not isinstance(val, list) or not all(isinstance(item, str) for item in val):
                issues.append(
                    ValidationIssue(
                        category=ValidationErrorCategory.INVALID_METADATA,
                        field=f"metadata.{list_key}",
                        message=f"metadata.{list_key} must be an array of strings",
                        severity="error",
                    )
                )

    if "source_fields" in metadata and metadata["source_fields"] is not None:
        if not isinstance(metadata["source_fields"], dict):
            issues.append(
                ValidationIssue(
                    category=ValidationErrorCategory.INVALID_METADATA,
                    field="metadata.source_fields",
                    message="metadata.source_fields must be a JSON object",
                    severity="error",
                )
            )

    return issues


def validate_ingestion_envelope(
    payload: Any,
    *,
    verify_raw_hash: bool = True,
    max_skew_seconds: int = DEFAULT_FUTURE_SKEW_SECONDS,
    now_utc: Optional[datetime] = None,
) -> IngestionValidationResult:
    """
    Validate an incoming ingestion envelope dictionary against IngestionEnvelope
    and Stage 1 / Stage 4 data contracts.

    Returns a structured IngestionValidationResult with sanitized error messages.
    """
    errors: List[ValidationIssue] = []
    warnings: List[ValidationIssue] = []

    if not isinstance(payload, dict):
        errors.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field="envelope",
                message="Ingestion payload must be a JSON object",
                severity="error",
            )
        )
        return IngestionValidationResult(
            valid=False,
            disposition=IngestionDisposition.REJECTED,
            errors=errors,
        )

    required_fields = (
        "ingestion_id",
        "source_type",
        "sensor_id",
        "ingest_time",
        "raw_hash",
        "raw_payload",
    )
    for field_name in required_fields:
        if field_name not in payload or payload[field_name] is None:
            errors.append(
                ValidationIssue(
                    category=ValidationErrorCategory.MISSING_REQUIRED_FIELD,
                    field=field_name,
                    message=f"Missing required field '{field_name}'",
                    severity="error",
                )
            )

    if errors:
        return IngestionValidationResult(
            valid=False,
            disposition=IngestionDisposition.REJECTED,
            errors=errors,
        )

    # Validate source_type and detect unsupported formats early
    raw_source_type = payload["source_type"]
    try:
        source_type = (
            raw_source_type
            if isinstance(raw_source_type, SourceTypeEnum)
            else SourceTypeEnum(raw_source_type)
        )
    except ValueError:
        errors.append(
            ValidationIssue(
                category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
                field="source_type",
                message="Unsupported or unrecognized source_type",
                severity="error",
            )
        )
        return IngestionValidationResult(
            valid=False,
            disposition=IngestionDisposition.UNSUPPORTED,
            errors=errors,
        )

    if source_type in UNSUPPORTED_SOURCE_TYPES:
        errors.append(
            ValidationIssue(
                category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
                field="source_type",
                message=f"source_type '{source_type.value}' is not supported for automated normalization",
                severity="error",
            )
        )
        return IngestionValidationResult(
            valid=False,
            disposition=IngestionDisposition.UNSUPPORTED,
            errors=errors,
        )

    # Validate ingestion_id (UUID v4)
    ingestion_id = payload["ingestion_id"]
    valid_ingestion_id: Optional[str] = None
    if not _is_valid_uuid_v4(ingestion_id):
        errors.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_IDENTIFIER,
                field="ingestion_id",
                message="ingestion_id must be a valid RFC 4122 UUID v4",
                severity="error",
            )
        )
    else:
        valid_ingestion_id = ingestion_id

    # Validate sensor_id
    sensor_id = payload["sensor_id"]
    if not isinstance(sensor_id, str) or not sensor_id.strip():
        errors.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_IDENTIFIER,
                field="sensor_id",
                message="sensor_id must be a non-empty string",
                severity="error",
            )
        )
    elif len(sensor_id) > MAX_SENSOR_ID_LENGTH:
        errors.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_IDENTIFIER,
                field="sensor_id",
                message=f"sensor_id exceeds maximum length of {MAX_SENSOR_ID_LENGTH} characters",
                severity="error",
            )
        )

    # Validate ingest_time (ISO 8601 UTC)
    ingest_dt = _parse_iso8601_utc(payload["ingest_time"])
    if ingest_dt is None:
        errors.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_TIMESTAMP,
                field="ingest_time",
                message="ingest_time must be a valid ISO 8601 UTC timestamp",
                severity="error",
            )
        )
    else:
        ref_now = now_utc or datetime.now(timezone.utc)
        if ingest_dt > ref_now + timedelta(seconds=max_skew_seconds):
            warnings.append(
                ValidationIssue(
                    category=ValidationErrorCategory.INVALID_TIMESTAMP,
                    field="ingest_time",
                    message="ingest_time is ahead of server clock beyond skew tolerance",
                    severity="warning",
                )
            )

    # Validate raw_hash format
    raw_hash = payload["raw_hash"]
    valid_raw_hash: Optional[str] = None
    if not isinstance(raw_hash, str) or not _SHA256_PATTERN.match(raw_hash):
        errors.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_IDENTIFIER,
                field="raw_hash",
                message="raw_hash must match 'sha256:<64-lowercase-hex>'",
                severity="error",
            )
        )
    else:
        valid_raw_hash = raw_hash

    # Validate raw_payload (non-empty string, size policy, hash integrity, structure)
    raw_payload = payload["raw_payload"]
    raw_truncated = False
    if not isinstance(raw_payload, str) or not raw_payload.strip():
        errors.append(
            ValidationIssue(
                category=ValidationErrorCategory.MALFORMED_PAYLOAD,
                field="raw_payload",
                message="raw_payload must be a non-empty string",
                severity="error",
            )
        )
    else:
        payload_bytes = len(raw_payload.encode("utf-8"))
        if payload_bytes > MAX_RAW_PAYLOAD_BYTES:
            raw_truncated = True
            warnings.append(
                ValidationIssue(
                    category=ValidationErrorCategory.PAYLOAD_TRUNCATED,
                    field="raw_payload",
                    message=f"raw_payload exceeds {MAX_RAW_PAYLOAD_BYTES} bytes and requires truncation",
                    severity="warning",
                )
            )

        if verify_raw_hash and valid_raw_hash is not None:
            expected_hash = compute_raw_hash(raw_payload)
            if valid_raw_hash != expected_hash:
                errors.append(
                    ValidationIssue(
                        category=ValidationErrorCategory.HASH_MISMATCH,
                        field="raw_hash",
                        message="raw_hash does not match SHA-256 digest of raw_payload",
                        severity="error",
                    )
                )

        struct_issue = _check_payload_structure(source_type, raw_payload)
        if struct_issue is not None:
            errors.append(struct_issue)

    # Optional metadata sanity check if caller includes an auxiliary metadata bag
    if "metadata" in payload and payload["metadata"] is not None:
        errors.extend(validate_event_metadata(payload["metadata"]))

    if errors:
        return IngestionValidationResult(
            valid=False,
            disposition=IngestionDisposition.REJECTED,
            ingestion_id=valid_ingestion_id,
            raw_hash=valid_raw_hash,
            raw_truncated=raw_truncated,
            errors=errors,
            warnings=warnings,
        )

    # Construct validated IngestionEnvelope via existing Pydantic schema
    try:
        envelope = IngestionEnvelope(
            ingestion_id=payload["ingestion_id"],
            source_type=source_type,
            sensor_id=payload["sensor_id"].strip(),
            ingest_time=payload["ingest_time"],
            raw_hash=payload["raw_hash"],
            raw_payload=payload["raw_payload"],
        )
    except Exception:
        errors.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field="envelope",
                message="Envelope failed schema validation",
                severity="error",
            )
        )
        return IngestionValidationResult(
            valid=False,
            disposition=IngestionDisposition.REJECTED,
            ingestion_id=valid_ingestion_id,
            raw_hash=valid_raw_hash,
            raw_truncated=raw_truncated,
            errors=errors,
            warnings=warnings,
        )

    disposition = (
        IngestionDisposition.ACCEPTED_WITH_WARNINGS
        if warnings
        else IngestionDisposition.ACCEPTED
    )
    return IngestionValidationResult(
        valid=True,
        disposition=disposition,
        envelope=envelope,
        ingestion_id=envelope.ingestion_id,
        raw_hash=envelope.raw_hash,
        raw_truncated=raw_truncated,
        errors=[],
        warnings=warnings,
    )


class IngestionEnvelopeValidator:
    """
    Focused validation service combining schema validation with duplicate-identity tracking.
    Designed for direct integration with DJ's backend ingestion endpoint.
    """

    def __init__(
        self,
        duplicate_tracker: Optional[DuplicateTrackerProtocol] = None,
        *,
        verify_raw_hash: bool = True,
        max_skew_seconds: int = DEFAULT_FUTURE_SKEW_SECONDS,
    ) -> None:
        self._tracker = duplicate_tracker or InMemoryDuplicateTracker()
        self._verify_raw_hash = verify_raw_hash
        self._max_skew_seconds = max_skew_seconds

    async def validate_envelope(
        self, payload: Any, *, now_utc: Optional[datetime] = None
    ) -> IngestionValidationResult:
        """
        Validate an incoming envelope and flag duplicates without silently dropping events.
        """
        result = validate_ingestion_envelope(
            payload,
            verify_raw_hash=self._verify_raw_hash,
            max_skew_seconds=self._max_skew_seconds,
            now_utc=now_utc,
        )
        if not result.valid or result.envelope is None:
            return result

        is_dup, dup_type = await self._tracker.check_and_record(
            result.envelope.ingestion_id, result.envelope.raw_hash
        )
        if is_dup:
            result.is_duplicate = True
            result.duplicate_type = dup_type
            result.warnings.append(
                ValidationIssue(
                    category=ValidationErrorCategory.DUPLICATE_EVENT,
                    field=dup_type or "raw_hash",
                    message=f"Duplicate {dup_type} observed; event flagged for downstream tracking",
                    severity="warning",
                )
            )
            result.disposition = IngestionDisposition.ACCEPTED_WITH_WARNINGS

        return result
