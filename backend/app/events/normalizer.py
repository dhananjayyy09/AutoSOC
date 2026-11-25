"""
AutoSOC - Deterministic Security Event Normalizer (Day 7)

Implements EventNormalizerProtocol and produces NormalizationResult objects
for backend and frontend consumption without altering raw payloads, inventing
threat classifications, or performing detection/enrichment.
"""

from datetime import datetime, timezone
import ipaddress
import ntpath
import posixpath
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from app.events.parser import DeterministicSourceParser, SUPPORTED_PARSER_SOURCES
from app.events.schemas import (
    BaseModel,
    EventCategoryEnum,
    Field,
    IngestionEnvelope,
    NormalizationStatusEnum,
    NormalizedSecurityEvent,
    ProtocolEnum,
    SourceTypeEnum,
)
from app.events.validation import (
    ValidationErrorCategory,
    ValidationIssue,
    validate_ingestion_envelope,
)

PIPELINE_VERSION = "0.2.0"

_SURICATA_EVENT_TYPE_MAP: Dict[str, str] = {
    "alert": "alert.ids",
    "flow": "network.connection",
    "dns": "network.dns",
    "http": "network.http",
    "tls": "network.connection",
    "fileinfo": "file.create",
    "anomaly": "alert.anomaly",
    "netflow": "network.connection",
}

_SURICATA_SEVERITY_MAP: Dict[int, int] = {
    1: 5,
    2: 4,
    3: 3,
    4: 2,
}

_SYSMON_EVENT_ID_MAP: Dict[str, str] = {
    "1": "process.create",
    "2": "file.modify",
    "3": "network.connection",
    "5": "process.terminate",
    "6": "file.create",
    "7": "file.create",
    "8": "process.inject",
    "9": "file.modify",
    "10": "process.inject",
    "11": "file.create",
    "12": "registry.create",
    "13": "registry.modify",
    "15": "file.create",
    "22": "network.dns",
    "23": "file.delete",
    "25": "process.inject",
}

_SYSMON_FILTERED_EVENT_IDS = frozenset({"4", "16"})

_SYSMON_SEVERITY_MAP: Dict[str, int] = {
    "process.inject": 3,
    "network.connection": 2,
    "registry.modify": 2,
}

_ZEEK_LOG_TYPE_MAP: Dict[str, str] = {
    "conn": "network.connection",
    "dns": "network.dns",
    "http": "network.http",
    "ssl": "network.connection",
    "tls": "network.connection",
    "files": "file.create",
    "weird": "network.alert",
    "notice": "alert.ids",
}

_ZEEK_NOTICE_SEVERITY_MAP: Dict[str, int] = {
    "notice": 2,
    "warning": 3,
    "critical": 4,
}


class NormalizationResult(BaseModel):
    """Structured normalization outcome shared by backend and frontend."""

    normalization_status: NormalizationStatusEnum = Field(
        description="Deterministic normalization status"
    )
    event: Optional[NormalizedSecurityEvent] = Field(
        default=None, description="Normalized security event when normalization succeeds"
    )
    ingestion_id: Optional[str] = Field(
        default=None, description="Delivery attempt UUID from IngestionEnvelope"
    )
    sensor_id: Optional[str] = Field(
        default=None, description="Originating sensor identifier from IngestionEnvelope"
    )
    source_type: Optional[str] = Field(
        default=None, description="Source type string from envelope"
    )
    raw_hash: Optional[str] = Field(
        default=None, description="SHA-256 digest of unmodified raw payload"
    )
    errors: List[ValidationIssue] = Field(
        default_factory=list, description="Blocking normalization/validation errors"
    )
    warnings: List[ValidationIssue] = Field(
        default_factory=list, description="Non-blocking normalization/validation warnings"
    )


def _format_utc_ms(dt: datetime) -> str:
    utc_dt = dt.astimezone(timezone.utc)
    ms = utc_dt.microsecond // 1000
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"


def _normalize_timestamp(value: Any) -> Optional[str]:
    """Convert ISO 8601 (with timezone) or Unix epoch float/int into ISO 8601 UTC."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
            return _format_utc_ms(dt)
        except (ValueError, OverflowError, OSError):
            return None

    if not isinstance(value, str) or not value.strip():
        return None

    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None

    if dt.tzinfo is None:
        return None
    return _format_utc_ms(dt)


def _normalize_ip(
    value: Any, field_name: str, warnings: List[ValidationIssue]
) -> Optional[str]:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str):
        warnings.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field=field_name,
                message=f"Invalid IP address type in '{field_name}'; set to null",
                severity="warning",
            )
        )
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        warnings.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field=field_name,
                message=f"Invalid IP address in '{field_name}'; set to null",
                severity="warning",
            )
        )
        return None


def _normalize_port(
    value: Any, field_name: str, warnings: List[ValidationIssue]
) -> Optional[int]:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool):
        warnings.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field=field_name,
                message=f"Invalid port boolean in '{field_name}'; set to null",
                severity="warning",
            )
        )
        return None
    try:
        port = int(value)
    except (ValueError, TypeError):
        warnings.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field=field_name,
                message=f"Invalid port value in '{field_name}'; set to null",
                severity="warning",
            )
        )
        return None

    if port < 0 or port > 65535:
        warnings.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field=field_name,
                message=f"Port out of range [0, 65535] in '{field_name}'; set to null",
                severity="warning",
            )
        )
        return None
    return port


def _normalize_protocol(
    value: Any, warnings: List[ValidationIssue]
) -> Optional[ProtocolEnum]:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str):
        warnings.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field="protocol",
                message="Invalid protocol type; mapped to 'other'",
                severity="warning",
            )
        )
        return ProtocolEnum.OTHER

    lowered = value.strip().lower()
    try:
        return ProtocolEnum(lowered)
    except ValueError:
        warnings.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field="protocol",
                message=f"Unrecognized protocol '{lowered}'; mapped to 'other'",
                severity="warning",
            )
        )
        return ProtocolEnum.OTHER


def _normalize_domain(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().rstrip(".").lower()
    return cleaned or None


def _extract_basename(path_value: Any) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(path_value, str) or not path_value.strip():
        return None, None
    full_path = path_value.strip()
    if "\\" in full_path:
        basename = ntpath.basename(full_path)
    else:
        basename = posixpath.basename(full_path)
    return (basename or None), full_path


def _normalize_user(value: Any) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(value, str) or not value.strip():
        return None, None
    raw = value.strip()
    if "\\" in raw:
        domain_part, user_part = raw.split("\\", 1)
        return (user_part.lower() or None), (domain_part or None)
    return raw.lower(), None


def _derive_event_category(event_type: str) -> EventCategoryEnum:
    prefix = event_type.split(".", 1)[0]
    try:
        return EventCategoryEnum(prefix)
    except ValueError:
        return EventCategoryEnum.UNKNOWN


def _parse_sysmon_hashes(hashes_str: Any) -> Tuple[Optional[str], Optional[Dict[str, str]]]:
    if not isinstance(hashes_str, str) or not hashes_str.strip():
        return None, None
    hashes_map: Dict[str, str] = {}
    for part in hashes_str.split(","):
        if "=" not in part:
            continue
        algo, digest = part.split("=", 1)
        algo_clean = algo.strip().lower()
        digest_clean = digest.strip().lower()
        if algo_clean and digest_clean:
            hashes_map[algo_clean] = digest_clean

    if not hashes_map:
        return None, None
    for preferred in ("sha256", "sha1", "md5"):
        if preferred in hashes_map:
            return f"{preferred}:{hashes_map[preferred]}", hashes_map
    first_algo = next(iter(hashes_map))
    return f"{first_algo}:{hashes_map[first_algo]}", hashes_map


def _safe_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _map_suricata(
    parsed: Dict[str, Any],
    envelope: Dict[str, Any],
    warnings: List[ValidationIssue],
) -> Tuple[Optional[Dict[str, Any]], Optional[ValidationIssue]]:
    timestamp = _normalize_timestamp(parsed.get("timestamp"))
    if timestamp is None:
        return None, ValidationIssue(
            category=ValidationErrorCategory.INVALID_TIMESTAMP,
            field="timestamp",
            message="Suricata event missing or invalid UTC ISO 8601 'timestamp'",
            severity="error",
        )

    raw_event_type = parsed.get("event_type")
    if isinstance(raw_event_type, str) and raw_event_type in _SURICATA_EVENT_TYPE_MAP:
        event_type = _SURICATA_EVENT_TYPE_MAP[raw_event_type]
    else:
        event_type = "unknown"
        warnings.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field="event_type",
                message="Unrecognized Suricata event_type; mapped to 'unknown'",
                severity="warning",
            )
        )

    dns_obj = parsed.get("dns") if isinstance(parsed.get("dns"), dict) else {}
    http_obj = parsed.get("http") if isinstance(parsed.get("http"), dict) else {}
    tls_obj = parsed.get("tls") if isinstance(parsed.get("tls"), dict) else {}
    fileinfo_obj = parsed.get("fileinfo") if isinstance(parsed.get("fileinfo"), dict) else {}
    alert_obj = parsed.get("alert") if isinstance(parsed.get("alert"), dict) else {}

    domain = _normalize_domain(
        dns_obj.get("rrname") or http_obj.get("hostname") or tls_obj.get("sni")
    )

    file_hash: Optional[str] = None
    hashes_map: Optional[Dict[str, str]] = None
    if isinstance(fileinfo_obj.get("sha256"), str) and fileinfo_obj["sha256"].strip():
        sha = fileinfo_obj["sha256"].strip().lower()
        file_hash = f"sha256:{sha}"
        hashes_map = {"sha256": sha}
    elif isinstance(fileinfo_obj.get("md5"), str) and fileinfo_obj["md5"].strip():
        md5 = fileinfo_obj["md5"].strip().lower()
        file_hash = f"md5:{md5}"
        hashes_map = {"md5": md5}

    source_severity = alert_obj.get("severity")
    severity = 1
    if raw_event_type == "alert" and isinstance(source_severity, int) and not isinstance(source_severity, bool):
        severity = _SURICATA_SEVERITY_MAP.get(source_severity, 1)

    host_val = parsed.get("host")
    host = host_val.strip() if isinstance(host_val, str) and host_val.strip() else envelope["sensor_id"]

    mapped_keys = {"timestamp", "event_type", "host", "src_ip", "dest_ip", "src_port", "dest_port", "proto"}
    source_fields = {k: v for k, v in parsed.items() if k not in mapped_keys}
    if event_type == "unknown" and raw_event_type is not None:
        source_fields["original_event_type"] = raw_event_type

    flow_id = parsed.get("flow_id")
    source_event_id = f"flow_id:{flow_id}" if flow_id is not None else None

    metadata: Dict[str, Any] = {
        "ingest_time": envelope["ingest_time"],
        "pipeline_version": PIPELINE_VERSION,
        "raw_hash": envelope["raw_hash"],
        "sensor_id": envelope["sensor_id"],
        "source_event_id": source_event_id,
        "source_severity": source_severity,
        "hashes": hashes_map,
        "source_fields": source_fields,
        "tags": [],
    }

    return {
        "timestamp": timestamp,
        "source": SourceTypeEnum.SURICATA,
        "event_category": _derive_event_category(event_type),
        "event_type": event_type,
        "host": host,
        "severity": severity,
        "user": None,
        "source_ip": _normalize_ip(parsed.get("src_ip"), "source_ip", warnings),
        "destination_ip": _normalize_ip(parsed.get("dest_ip"), "destination_ip", warnings),
        "source_port": _normalize_port(parsed.get("src_port"), "source_port", warnings),
        "destination_port": _normalize_port(parsed.get("dest_port"), "destination_port", warnings),
        "protocol": _normalize_protocol(parsed.get("proto") or parsed.get("app_proto"), warnings),
        "process": None,
        "file_hash": file_hash,
        "domain": domain,
        "command_line": None,
        "metadata": metadata,
    }, None


def _map_sysmon(
    parsed: Dict[str, Any],
    envelope: Dict[str, Any],
    warnings: List[ValidationIssue],
) -> Tuple[Optional[Dict[str, Any]], Optional[ValidationIssue]]:
    event_id_str = str(parsed.get("EventID", "")).strip()
    if event_id_str in _SYSMON_FILTERED_EVENT_IDS:
        return None, ValidationIssue(
            category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
            field="EventID",
            message=f"Sysmon EventID {event_id_str} is filtered and not normalized per contract",
            severity="error",
        )

    timestamp = _normalize_timestamp(parsed.get("TimeCreated"))
    if timestamp is None:
        return None, ValidationIssue(
            category=ValidationErrorCategory.INVALID_TIMESTAMP,
            field="timestamp",
            message="Sysmon event missing or invalid UTC ISO 8601 'System.TimeCreated'",
            severity="error",
        )

    if event_id_str in _SYSMON_EVENT_ID_MAP:
        event_type = _SYSMON_EVENT_ID_MAP[event_id_str]
    else:
        event_type = "unknown"
        warnings.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field="event_type",
                message="Unrecognized Sysmon EventID; mapped to 'unknown'",
                severity="warning",
            )
        )

    event_data = parsed.get("EventData") if isinstance(parsed.get("EventData"), dict) else {}
    computer = parsed.get("Computer")
    host = computer.strip() if isinstance(computer, str) and computer.strip() else envelope["sensor_id"]

    user, user_domain = _normalize_user(event_data.get("User"))
    process, process_path = _extract_basename(event_data.get("Image"))
    parent_process, _ = _extract_basename(event_data.get("ParentImage"))
    file_hash, hashes_map = _parse_sysmon_hashes(event_data.get("Hashes"))

    cmd_raw = event_data.get("CommandLine")
    command_line = cmd_raw.strip() if isinstance(cmd_raw, str) and cmd_raw.strip() else None

    mapped_event_data_keys = {
        "User",
        "Image",
        "CommandLine",
        "Hashes",
        "SourceIp",
        "DestinationIp",
        "SourcePort",
        "DestinationPort",
        "Protocol",
        "QueryName",
        "ProcessId",
        "ParentProcessId",
        "ParentImage",
    }
    source_fields = {k: v for k, v in event_data.items() if k not in mapped_event_data_keys}
    source_fields["EventID"] = event_id_str
    if event_type == "unknown":
        source_fields["original_event_type"] = f"sysmon_event_id_{event_id_str}"

    severity = _SYSMON_SEVERITY_MAP.get(event_type, 1)

    metadata: Dict[str, Any] = {
        "ingest_time": envelope["ingest_time"],
        "pipeline_version": PIPELINE_VERSION,
        "raw_hash": envelope["raw_hash"],
        "sensor_id": envelope["sensor_id"],
        "source_event_id": parsed.get("EventRecordID"),
        "process_path": process_path,
        "parent_process": parent_process,
        "pid": _safe_int(event_data.get("ProcessId")),
        "parent_pid": _safe_int(event_data.get("ParentProcessId")),
        "user_domain": user_domain,
        "hashes": hashes_map,
        "source_fields": source_fields,
        "tags": [],
    }

    return {
        "timestamp": timestamp,
        "source": SourceTypeEnum.SYSMON,
        "event_category": _derive_event_category(event_type),
        "event_type": event_type,
        "host": host,
        "severity": severity,
        "user": user,
        "source_ip": _normalize_ip(event_data.get("SourceIp"), "source_ip", warnings),
        "destination_ip": _normalize_ip(event_data.get("DestinationIp"), "destination_ip", warnings),
        "source_port": _normalize_port(event_data.get("SourcePort"), "source_port", warnings),
        "destination_port": _normalize_port(event_data.get("DestinationPort"), "destination_port", warnings),
        "protocol": _normalize_protocol(event_data.get("Protocol"), warnings),
        "process": process,
        "file_hash": file_hash,
        "domain": _normalize_domain(event_data.get("QueryName")),
        "command_line": command_line,
        "metadata": metadata,
    }, None


def _infer_zeek_log_type(parsed: Dict[str, Any]) -> Optional[str]:
    explicit = parsed.get("_path") or parsed.get("log_type")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip().lower()
    if "query" in parsed:
        return "dns"
    if "method" in parsed and "uri" in parsed:
        return "http"
    if "server_name" in parsed or "cipher" in parsed:
        return "ssl"
    if "fuid" in parsed or "mime_type" in parsed:
        return "files"
    if "note" in parsed:
        return "notice"
    if "name" in parsed and "notice" in parsed:
        return "weird"
    if "conn_state" in parsed or "proto" in parsed:
        return "conn"
    return None


def _map_zeek(
    parsed: Dict[str, Any],
    envelope: Dict[str, Any],
    warnings: List[ValidationIssue],
) -> Tuple[Optional[Dict[str, Any]], Optional[ValidationIssue]]:
    timestamp = _normalize_timestamp(parsed.get("ts"))
    if timestamp is None:
        return None, ValidationIssue(
            category=ValidationErrorCategory.INVALID_TIMESTAMP,
            field="timestamp",
            message="Zeek event missing or invalid 'ts' timestamp",
            severity="error",
        )

    log_type = _infer_zeek_log_type(parsed)
    if log_type and log_type in _ZEEK_LOG_TYPE_MAP:
        event_type = _ZEEK_LOG_TYPE_MAP[log_type]
    else:
        event_type = "unknown"
        warnings.append(
            ValidationIssue(
                category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                field="event_type",
                message="Unrecognized Zeek log type; mapped to 'unknown'",
                severity="warning",
            )
        )

    file_hash: Optional[str] = None
    hashes_map: Dict[str, str] = {}
    for algo in ("sha256", "sha1", "md5"):
        val = parsed.get(algo)
        if isinstance(val, str) and val.strip():
            hashes_map[algo] = val.strip().lower()
    for preferred in ("sha256", "sha1", "md5"):
        if preferred in hashes_map:
            file_hash = f"{preferred}:{hashes_map[preferred]}"
            break

    severity = 1
    if log_type == "weird":
        severity = 2
    elif log_type == "notice":
        notice_sev = str(parsed.get("severity", "")).strip().lower()
        severity = _ZEEK_NOTICE_SEVERITY_MAP.get(notice_sev, 2)

    mapped_keys = {
        "ts",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "query",
        "host",
        "server_name",
        "sha256",
        "sha1",
        "md5",
    }
    source_fields = {k: v for k, v in parsed.items() if k not in mapped_keys}
    if event_type == "unknown" and log_type is not None:
        source_fields["original_event_type"] = log_type

    metadata: Dict[str, Any] = {
        "ingest_time": envelope["ingest_time"],
        "pipeline_version": PIPELINE_VERSION,
        "raw_hash": envelope["raw_hash"],
        "sensor_id": envelope["sensor_id"],
        "source_event_id": parsed.get("uid") if isinstance(parsed.get("uid"), str) else None,
        "hashes": hashes_map or None,
        "source_fields": source_fields,
        "tags": [],
    }

    return {
        "timestamp": timestamp,
        "source": SourceTypeEnum.ZEEK,
        "event_category": _derive_event_category(event_type),
        "event_type": event_type,
        "host": envelope["sensor_id"],
        "severity": severity,
        "user": None,
        "source_ip": _normalize_ip(parsed.get("id.orig_h"), "source_ip", warnings),
        "destination_ip": _normalize_ip(parsed.get("id.resp_h"), "destination_ip", warnings),
        "source_port": _normalize_port(parsed.get("id.orig_p"), "source_port", warnings),
        "destination_port": _normalize_port(parsed.get("id.resp_p"), "destination_port", warnings),
        "protocol": _normalize_protocol(parsed.get("service") or parsed.get("proto"), warnings),
        "process": None,
        "file_hash": file_hash,
        "domain": _normalize_domain(
            parsed.get("query") or parsed.get("host") or parsed.get("server_name")
        ),
        "command_line": None,
        "metadata": metadata,
    }, None


class DeterministicEventNormalizer:
    """
    Deterministic normalizer implementing EventNormalizerProtocol and providing
    structured NormalizationResult responses for backend and frontend use.
    """

    def __init__(self, parser: Optional[DeterministicSourceParser] = None) -> None:
        self._parser = parser or DeterministicSourceParser()

    def normalize(
        self, parsed_event: Dict[str, Any], ingestion_envelope: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        EventNormalizerProtocol-compliant method mapping ParsedEvent + IngestionEnvelope
        into a NormalizedSecurityEvent dictionary.
        """
        source_type = str(ingestion_envelope.get("source_type", "")).lower()
        source_fields = parsed_event.get("source_fields", parsed_event)
        warnings: List[ValidationIssue] = []

        mapped, err = self._map_by_source(source_type, source_fields, ingestion_envelope, warnings)
        if err is not None or mapped is None:
            raise ValueError(err.message if err else "Normalization failed")

        event = NormalizedSecurityEvent(
            event_id=str(uuid.uuid4()),
            ingestion_id=ingestion_envelope["ingestion_id"],
            raw_event=ingestion_envelope["raw_payload"],
            **mapped,
        )
        return event.model_dump()

    def normalize_envelope(
        self,
        envelope: Union[IngestionEnvelope, Dict[str, Any]],
        *,
        event_id: Optional[str] = None,
        verify_raw_hash: bool = True,
    ) -> NormalizationResult:
        """
        Validate an IngestionEnvelope, parse raw_payload deterministically, and
        produce a structured NormalizationResult.
        """
        envelope_dict = envelope.model_dump() if isinstance(envelope, BaseModel) else envelope

        validation = validate_ingestion_envelope(
            envelope_dict, verify_raw_hash=verify_raw_hash
        )
        if not validation.valid or validation.envelope is None:
            status = (
                NormalizationStatusEnum.UNSUPPORTED
                if any(
                    e.category == ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE
                    for e in validation.errors
                )
                else NormalizationStatusEnum.FAILED
            )
            return NormalizationResult(
                normalization_status=status,
                ingestion_id=validation.ingestion_id,
                sensor_id=envelope_dict.get("sensor_id") if isinstance(envelope_dict, dict) else None,
                source_type=str(envelope_dict.get("source_type")) if isinstance(envelope_dict, dict) and envelope_dict.get("source_type") is not None else None,
                raw_hash=validation.raw_hash,
                errors=validation.errors,
                warnings=validation.warnings,
            )

        env = validation.envelope
        env_data = env.model_dump()
        source_type = env_data["source_type"]

        if source_type not in SUPPORTED_PARSER_SOURCES:
            return NormalizationResult(
                normalization_status=NormalizationStatusEnum.UNSUPPORTED,
                ingestion_id=env.ingestion_id,
                sensor_id=env.sensor_id,
                source_type=source_type,
                raw_hash=env.raw_hash,
                errors=[
                    ValidationIssue(
                        category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
                        field="source_type",
                        message=f"Source type '{source_type}' does not have a Day 7 normalization mapping",
                        severity="error",
                    )
                ],
                warnings=validation.warnings,
            )

        ok, parsed, parse_err = self._parser.parse(env.raw_payload, source_type)
        if not ok or parsed is None:
            return NormalizationResult(
                normalization_status=NormalizationStatusEnum.FAILED,
                ingestion_id=env.ingestion_id,
                sensor_id=env.sensor_id,
                source_type=source_type,
                raw_hash=env.raw_hash,
                errors=[
                    ValidationIssue(
                        category=ValidationErrorCategory.MALFORMED_PAYLOAD,
                        field="raw_payload",
                        message=parse_err or "Failed to parse raw_payload",
                        severity="error",
                    )
                ],
                warnings=validation.warnings,
            )

        warnings: List[ValidationIssue] = list(validation.warnings)
        mapped, map_err = self._map_by_source(source_type, parsed, env_data, warnings)
        if map_err is not None or mapped is None:
            status = (
                NormalizationStatusEnum.UNSUPPORTED
                if map_err and map_err.category == ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE
                else NormalizationStatusEnum.FAILED
            )
            return NormalizationResult(
                normalization_status=status,
                ingestion_id=env.ingestion_id,
                sensor_id=env.sensor_id,
                source_type=source_type,
                raw_hash=env.raw_hash,
                errors=[map_err] if map_err else [],
                warnings=warnings,
            )

        event = NormalizedSecurityEvent(
            event_id=event_id or str(uuid.uuid4()),
            ingestion_id=env.ingestion_id,
            raw_event=env.raw_payload,
            **mapped,
        )

        norm_status = (
            NormalizationStatusEnum.NORMALIZED_WITH_WARNINGS
            if warnings
            else NormalizationStatusEnum.NORMALIZED
        )
        return NormalizationResult(
            normalization_status=norm_status,
            event=event,
            ingestion_id=env.ingestion_id,
            sensor_id=env.sensor_id,
            source_type=source_type,
            raw_hash=env.raw_hash,
            errors=[],
            warnings=warnings,
        )

    @staticmethod
    def _map_by_source(
        source_type: str,
        parsed: Dict[str, Any],
        envelope: Dict[str, Any],
        warnings: List[ValidationIssue],
    ) -> Tuple[Optional[Dict[str, Any]], Optional[ValidationIssue]]:
        if source_type == "suricata":
            return _map_suricata(parsed, envelope, warnings)
        if source_type == "sysmon":
            return _map_sysmon(parsed, envelope, warnings)
        if source_type == "zeek":
            return _map_zeek(parsed, envelope, warnings)
        return None, ValidationIssue(
            category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
            field="source_type",
            message=f"Unsupported source_type '{source_type}'",
            severity="error",
        )
