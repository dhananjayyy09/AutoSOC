"""
AutoSOC - Deterministic Security Event Enricher (Day 9)

Extracts, normalizes, deduplicates, and enriches observables from normalized
security events using network-free deterministic provider logic while preserving
full provenance and leaving normalized and raw evidence completely unchanged.
"""

from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from app.events.schemas import BaseModel, NormalizationStatusEnum
from app.events.validation import ValidationErrorCategory, ValidationIssue
from app.threat_intelligence.providers import (
    DeterministicLocalEnrichmentProvider,
    EnrichmentProviderProtocol,
)
from app.threat_intelligence.schemas import (
    EnrichedObservable,
    EnrichmentStatusEnum,
    EventEnrichmentResult,
    ObservableTypeEnum,
)

MAX_OBSERVABLE_VALUE_LENGTH = 512
MAX_URL_LENGTH = 2048
MAX_COMMAND_LINE_SCAN_LENGTH = 8192

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?)*$"
)
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_URL_EXTRACT_RE = re.compile(r"https?://[^\s'\"<>\\`]+", re.IGNORECASE)

_HASH_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
}


def _utc_now_iso() -> str:
    dt = datetime.now(timezone.utc)
    ms = dt.microsecond // 1000
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"


def _has_control_chars(value: str) -> bool:
    return bool(_CONTROL_CHAR_RE.search(value))


def _normalize_ip_observable(raw_val: Any) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(raw_val, str) or not raw_val.strip():
        return None, "IP observable must be a non-empty string"
    candidate = raw_val.strip()
    if len(candidate) > MAX_OBSERVABLE_VALUE_LENGTH or _has_control_chars(candidate):
        return None, "IP observable failed length or control-character safety check"
    try:
        return str(ipaddress.ip_address(candidate)), None
    except ValueError:
        return None, "Invalid IP address format"


def _normalize_domain_observable(raw_val: Any) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(raw_val, str) or not raw_val.strip():
        return None, "Domain observable must be a non-empty string"
    candidate = raw_val.strip().rstrip(".").lower()
    if (
        not candidate
        or len(candidate) > 253
        or _has_control_chars(candidate)
        or not _DOMAIN_RE.match(candidate)
    ):
        return None, "Invalid domain hostname syntax"
    # Reject bare IPv4 literals mistakenly placed into domain field
    try:
        ipaddress.ip_address(candidate)
        return None, "Domain value is a bare IP address rather than a hostname"
    except ValueError:
        pass
    return candidate, None


def _normalize_url_observable(raw_val: Any) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(raw_val, str) or not raw_val.strip():
        return None, "URL observable must be a non-empty string"
    candidate = raw_val.strip()
    if len(candidate) > MAX_URL_LENGTH or _has_control_chars(candidate) or any(ch.isspace() for ch in candidate):
        return None, "URL observable failed length or whitespace safety check"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None, "Malformed URL syntax"

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return None, "Only http and https URL schemes are supported"
    if not parsed.hostname:
        return None, "URL missing hostname"

    hostname = parsed.hostname.lower().rstrip(".")
    # Strip any embedded userinfo from normalized URL while preserving port
    netloc = f"{hostname}:{parsed.port}" if parsed.port else hostname
    normalized = urlunsplit((scheme, netloc, parsed.path or "", parsed.query, parsed.fragment))
    return normalized, None


def _normalize_hash_observable(
    raw_val: Any, *, default_algo: Optional[str] = None
) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(raw_val, str) or not raw_val.strip():
        return None, "Hash observable must be a non-empty string"
    candidate = raw_val.strip().lower()
    if len(candidate) > MAX_OBSERVABLE_VALUE_LENGTH or _has_control_chars(candidate):
        return None, "Hash observable failed length or safety check"

    if ":" in candidate:
        algo, digest = candidate.split(":", 1)
    elif default_algo:
        algo, digest = default_algo.strip().lower(), candidate
    else:
        return None, "File hash missing algorithm prefix (expected sha256:/sha1:/md5:)"

    expected_len = _HASH_LENGTHS.get(algo)
    if expected_len is None:
        return None, "Unsupported hash algorithm"
    if len(digest) != expected_len or not _HEX_RE.match(digest):
        return None, "Malformed cryptographic hash digest"
    return f"{algo}:{digest}", None


def _extract_event_snapshot(event: Any) -> Optional[Dict[str, Any]]:
    """
    Create a read-only snapshot from a NormalizedSecurityEvent, NormalizedEventResponse,
    NormalizedEvent ORM model, or dict without mutating the source object.
    """
    if isinstance(event, dict):
        data = dict(event)
    elif isinstance(event, BaseModel):
        data = event.model_dump()
    elif hasattr(event, "model_dump") and callable(event.model_dump):
        data = event.model_dump()
    elif hasattr(event, "ingestion_id"):
        # Supports SQLAlchemy NormalizedEvent ORM instances cleanly
        meta = getattr(event, "event_metadata", None)
        if meta is None:
            meta = getattr(event, "metadata", {})
        data = {
            "event_id": getattr(event, "event_id", None),
            "ingestion_id": getattr(event, "ingestion_id", None),
            "normalization_status": getattr(event, "normalization_status", None),
            "source_ip": getattr(event, "source_ip", None),
            "destination_ip": getattr(event, "destination_ip", None),
            "domain": getattr(event, "domain", None),
            "file_hash": getattr(event, "file_hash", None),
            "command_line": getattr(event, "command_line", None),
            "metadata": dict(meta) if isinstance(meta, dict) else {},
        }
    else:
        return None

    # Normalize ORM `user_name` / dict `metadata`
    meta_raw = data.get("metadata")
    data["metadata"] = dict(meta_raw) if isinstance(meta_raw, dict) else {}
    return data


def _collect_candidate_observables(
    snapshot: Dict[str, Any], warnings: List[ValidationIssue]
) -> List[Tuple[ObservableTypeEnum, str, str, str]]:
    """
    Extract and validate candidate observables in deterministic field order.
    Returns list of (observable_type, normalized_value, original_value, field_path).
    """
    candidates: List[Tuple[ObservableTypeEnum, str, str, str]] = []

    def _add(obs_type: ObservableTypeEnum, norm: Optional[str], err: Optional[str], orig: Any, field_path: str) -> None:
        if err is not None:
            warnings.append(
                ValidationIssue(
                    category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                    field=field_path,
                    message=f"Skipped invalid observable in '{field_path}': {err}",
                    severity="warning",
                )
            )
        elif norm is not None:
            candidates.append((obs_type, norm, str(orig), field_path))

    for ip_field in ("source_ip", "destination_ip"):
        raw_ip = snapshot.get(ip_field)
        if raw_ip is not None:
            norm, err = _normalize_ip_observable(raw_ip)
            _add(ObservableTypeEnum.IP, norm, err, raw_ip, ip_field)

    raw_domain = snapshot.get("domain")
    if raw_domain is not None:
        norm, err = _normalize_domain_observable(raw_domain)
        _add(ObservableTypeEnum.DOMAIN, norm, err, raw_domain, "domain")

    raw_hash = snapshot.get("file_hash")
    if raw_hash is not None:
        norm, err = _normalize_hash_observable(raw_hash)
        _add(ObservableTypeEnum.FILE_HASH, norm, err, raw_hash, "file_hash")

    metadata = snapshot.get("metadata", {})
    hashes_dict = metadata.get("hashes")
    if isinstance(hashes_dict, dict):
        for algo_key in sorted(hashes_dict.keys()):
            val = hashes_dict[algo_key]
            if val is not None:
                norm, err = _normalize_hash_observable(val, default_algo=str(algo_key))
                _add(
                    ObservableTypeEnum.FILE_HASH,
                    norm,
                    err,
                    val,
                    f"metadata.hashes.{algo_key}",
                )

    source_fields = metadata.get("source_fields")
    if isinstance(source_fields, dict):
        url_candidates: List[Tuple[str, Any]] = []
        if "url" in source_fields:
            url_candidates.append(("metadata.source_fields.url", source_fields["url"]))
        http_obj = source_fields.get("http")
        if isinstance(http_obj, dict) and "url" in http_obj:
            url_candidates.append(("metadata.source_fields.http.url", http_obj["url"]))
        if "uri" in source_fields:
            url_candidates.append(("metadata.source_fields.uri", source_fields["uri"]))

        for field_path, val in url_candidates:
            if isinstance(val, str) and ("://" in val):
                norm, err = _normalize_url_observable(val)
                _add(ObservableTypeEnum.URL, norm, err, val, field_path)

    cmd_line = snapshot.get("command_line")
    if isinstance(cmd_line, str) and cmd_line.strip():
        bounded_cmd = cmd_line[:MAX_COMMAND_LINE_SCAN_LENGTH]
        for match in _URL_EXTRACT_RE.finditer(bounded_cmd):
            raw_url = match.group(0).rstrip(".,;)]}")
            norm, err = _normalize_url_observable(raw_url)
            _add(ObservableTypeEnum.URL, norm, err, raw_url, "command_line")

    return candidates


class DeterministicEventEnricher:
    """
    Deterministic security event enricher orchestrating observable extraction,
    normalization, deduplication, and provider invocation with full provenance.
    """

    def __init__(
        self, provider: Optional[EnrichmentProviderProtocol] = None
    ) -> None:
        self._provider: EnrichmentProviderProtocol = (
            provider or DeterministicLocalEnrichmentProvider()
        )

    async def enrich(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
        """EventEnricherProtocol-compliant async adapter returning serialized EventEnrichmentResult."""
        result = self.enrich_event(normalized_event)
        return result.model_dump()

    def enrich_event(
        self, event: Any, *, enriched_at: Optional[str] = None
    ) -> EventEnrichmentResult:
        """
        Enrich a normalized security event deterministically without modifying
        the input event or raw evidence.
        """
        timestamp_str = enriched_at or _utc_now_iso()
        snapshot = _extract_event_snapshot(event)
        if snapshot is None or not snapshot.get("ingestion_id"):
            return EventEnrichmentResult(
                enrichment_status=EnrichmentStatusEnum.FAILED,
                source_event_id=snapshot.get("event_id") if snapshot else None,
                ingestion_id=snapshot.get("ingestion_id") if snapshot else None,
                enriched_at=timestamp_str,
                provider=self._provider.provider_id,
                provider_version=self._provider.provider_version,
                live_lookup_performed=self._provider.is_live_lookup,
                observable_count=0,
                observables=[],
                errors=[
                    ValidationIssue(
                        category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                        field="event",
                        message="Input must be a valid normalized event containing ingestion_id",
                        severity="error",
                    )
                ],
            )

        norm_status = snapshot.get("normalization_status")
        if hasattr(norm_status, "value"):
            norm_status = norm_status.value
        if norm_status in (
            NormalizationStatusEnum.FAILED.value,
            NormalizationStatusEnum.UNSUPPORTED.value,
        ):
            return EventEnrichmentResult(
                enrichment_status=EnrichmentStatusEnum.SKIPPED,
                source_event_id=snapshot.get("event_id"),
                ingestion_id=snapshot.get("ingestion_id"),
                enriched_at=timestamp_str,
                provider=self._provider.provider_id,
                provider_version=self._provider.provider_version,
                live_lookup_performed=self._provider.is_live_lookup,
                observable_count=0,
                observables=[],
                warnings=[
                    ValidationIssue(
                        category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                        field="normalization_status",
                        message=f"Enrichment skipped for event with normalization_status='{norm_status}'",
                        severity="warning",
                    )
                ],
            )

        warnings: List[ValidationIssue] = []
        candidates = _collect_candidate_observables(snapshot, warnings)

        # Deduplicate within the event by (observable_type, normalized_value)
        dedup_order: List[Tuple[ObservableTypeEnum, str]] = []
        grouped: Dict[Tuple[ObservableTypeEnum, str], Dict[str, Any]] = {}

        for obs_type, norm_val, orig_val, field_path in candidates:
            key = (obs_type, norm_val)
            if key not in grouped:
                dedup_order.append(key)
                grouped[key] = {
                    "primary_original": orig_val,
                    "source_fields": [field_path],
                    "original_values": [orig_val],
                }
            else:
                entry = grouped[key]
                if field_path not in entry["source_fields"]:
                    entry["source_fields"].append(field_path)
                if orig_val not in entry["original_values"]:
                    entry["original_values"].append(orig_val)

        enriched_list: List[EnrichedObservable] = []
        for key in dedup_order:
            obs_type, norm_val = key
            if not self._provider.supports_observable(obs_type):
                warnings.append(
                    ValidationIssue(
                        category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
                        field=grouped[key]["source_fields"][0],
                        message=f"Provider '{self._provider.provider_id}' does not support '{obs_type.value}'",
                        severity="warning",
                    )
                )
                continue

            entry = grouped[key]
            enriched_obs = self._provider.enrich_observable(
                observable_type=obs_type,
                normalized_value=norm_val,
                original_value=entry["primary_original"],
                source_fields=entry["source_fields"],
                original_values=entry["original_values"],
                source_event_id=snapshot.get("event_id"),
                ingestion_id=snapshot["ingestion_id"],
            )
            if enriched_obs is not None:
                enriched_list.append(enriched_obs)

        if enriched_list and warnings:
            status = EnrichmentStatusEnum.ENRICHED_PARTIAL
        elif enriched_list:
            status = EnrichmentStatusEnum.ENRICHED
        elif warnings:
            status = EnrichmentStatusEnum.ENRICHED_PARTIAL
        else:
            status = EnrichmentStatusEnum.NO_OBSERVABLES

        return EventEnrichmentResult(
            enrichment_status=status,
            source_event_id=snapshot.get("event_id"),
            ingestion_id=snapshot.get("ingestion_id"),
            enriched_at=timestamp_str,
            provider=self._provider.provider_id,
            provider_version=self._provider.provider_version,
            live_lookup_performed=self._provider.is_live_lookup,
            observable_count=len(enriched_list),
            observables=enriched_list,
            warnings=warnings,
            errors=[],
        )
