"""
AutoSOC - Normalized Security Event and Telemetry Schemas

Authoritative data contracts for security event normalization, ingestion envelopes,
parsed event envelopes, and feature representations.
Conforms to docs/security/security-event-model.md and docs/security/security-data-contract.md.
"""

from enum import Enum
from typing import Optional, List, Dict, Any, Union
from uuid import UUID
from datetime import datetime

try:
    from pydantic import BaseModel, Field, ConfigDict
    PYDANTIC_V2 = True
except ImportError:
    PYDANTIC_V2 = False

    class _FieldInfo:
        def __init__(self, default=..., default_factory=None, ge=None, le=None, description=None):
            self.default = default
            self.default_factory = default_factory
            self.ge = ge
            self.le = le
            self.description = description

    def Field(default=..., *, default_factory=None, ge=None, le=None, description=None, **kwargs: Any) -> Any:
        return _FieldInfo(default=default, default_factory=default_factory, ge=ge, le=le, description=description)

    class BaseModel:
        def __init__(self, **data: Any):
            cls = self.__class__
            annotations = getattr(cls, "__annotations__", {})
            for attr_name in annotations:
                field_def = getattr(cls, attr_name, None)
                if attr_name in data:
                    val = data[attr_name]
                elif isinstance(field_def, _FieldInfo):
                    if field_def.default_factory is not None:
                        val = field_def.default_factory()
                    elif field_def.default is not ...:
                        val = field_def.default
                    else:
                        raise ValueError(f"Missing required field: {attr_name}")
                elif field_def is not None and not isinstance(field_def, _FieldInfo):
                    val = field_def
                else:
                    raise ValueError(f"Missing required field: {attr_name}")

                attr_type = annotations.get(attr_name)
                if isinstance(attr_type, type) and issubclass(attr_type, Enum) and val is not None:
                    val = attr_type(val)

                if isinstance(field_def, _FieldInfo):
                    if val is not None and field_def.ge is not None and val < field_def.ge:
                        raise ValueError(f"{attr_name} must be >= {field_def.ge}, got {val}")
                    if val is not None and field_def.le is not None and val > field_def.le:
                        raise ValueError(f"{attr_name} must be <= {field_def.le}, got {val}")

                setattr(self, attr_name, val)

            for k, v in data.items():
                if k not in annotations:
                    setattr(self, k, v)

        def model_dump(self) -> Dict[str, Any]:
            res = {}
            for k, v in self.__dict__.items():
                if not k.startswith("_"):
                    if isinstance(v, BaseModel):
                        res[k] = v.model_dump()
                    elif isinstance(v, list):
                        res[k] = [
                            item.model_dump() if isinstance(item, BaseModel)
                            else (item.value if isinstance(item, Enum) else item)
                            for item in v
                        ]
                    elif isinstance(v, Enum):
                        res[k] = v.value
                    else:
                        res[k] = v
            return res

        def dict(self) -> Dict[str, Any]:
            return self.model_dump()


class SourceTypeEnum(str, Enum):
    """Supported telemetry source systems."""
    SYSMON = "sysmon"
    ZEEK = "zeek"
    SURICATA = "suricata"
    WINDOWS_EVENT_LOG = "windows_event_log"
    AUDITD = "auditd"
    OSQUERY = "osquery"
    CUSTOM = "custom"


class EventCategoryEnum(str, Enum):
    """High-level taxonomy category for coarse event classification."""
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    REGISTRY = "registry"
    AUTH = "auth"
    ALERT = "alert"
    UNKNOWN = "unknown"


class ProtocolEnum(str, Enum):
    """Application or transport protocol enumeration."""
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"
    SMTP = "smtp"
    FTP = "ftp"
    SSH = "ssh"
    RDP = "rdp"
    SMB = "smb"
    OTHER = "other"


class IngestionEnvelope(BaseModel):
    """Transport envelope created at the ingestion layer upon receiving raw telemetry."""
    ingestion_id: str = Field(description="UUID v4 identifying this specific delivery attempt")
    source_type: SourceTypeEnum = Field(description="Telemetry source type for parser dispatch")
    sensor_id: str = Field(description="Configured identifier for originating sensor/host")
    ingest_time: str = Field(description="ISO 8601 UTC timestamp of receipt by AutoSOC")
    raw_hash: str = Field(description="SHA-256 hex digest of raw_payload bytes (sha256:<hex>)")
    raw_payload: str = Field(description="Unmodified raw payload string (max 64 KiB)")


class ParsedEvent(BaseModel):
    """Intermediate structured dictionary output produced by stateless source parsers."""
    ingestion_id: str = Field(description="Ingestion delivery UUID passed from transport envelope")
    source_type: SourceTypeEnum = Field(description="Telemetry source type")
    ingest_time: str = Field(description="ISO 8601 UTC ingestion timestamp")
    raw_hash: str = Field(description="SHA-256 payload fingerprint")
    source_fields: Dict[str, Any] = Field(default_factory=dict, description="Source-native parsed field dictionary")


class EventMetadata(BaseModel):
    """Reserved standard sub-keys and enrichment bag for normalized security events."""
    ingest_time: str = Field(description="ISO 8601 UTC receipt timestamp")
    pipeline_version: str = Field(description="Version of normalization pipeline")
    raw_hash: str = Field(description="SHA-256 payload digest for exact-duplicate recognition")
    source_event_id: Optional[str] = Field(default=None, description="Native source identifier (e.g. Sysmon EventRecordID, Zeek UID)")
    correlation_id: Optional[str] = Field(default=None, description="Logical transaction/session correlation ID")
    source_severity: Optional[Union[str, int]] = Field(default=None, description="Raw severity score prior to normalization")
    raw_truncated: bool = Field(default=False, description="True if raw_event exceeded 64 KiB and was truncated")
    possible_duplicate: Optional[bool] = Field(default=None, description="Flag indicating matched payload hash in dedup cache")
    timestamp_future: Optional[bool] = Field(default=None, description="Warning flag: event timestamp observed ahead of clock")
    timestamp_stale: Optional[bool] = Field(default=None, description="Warning flag: event timestamp older than retention window")
    is_internal_src: Optional[bool] = Field(default=None, description="True if source_ip belongs to RFC 1918 space")
    is_internal_dst: Optional[bool] = Field(default=None, description="True if destination_ip belongs to RFC 1918 space")
    geo: Optional[Dict[str, Any]] = Field(default=None, description="GeoIP metadata: country, city, asn, org")
    threat_intel: Optional[Dict[str, Any]] = Field(default=None, description="Threat intelligence enrichment indicators")
    mitre_techniques: List[str] = Field(default_factory=list, description="ATT&CK technique IDs associated with detections")
    alert_id: Optional[str] = Field(default=None, description="UUID of downstream Alert generated from this event")
    hashes: Optional[Dict[str, str]] = Field(default=None, description="Extracted hash algorithms (md5, sha1, sha256)")
    pid: Optional[int] = Field(default=None, description="Process ID")
    parent_pid: Optional[int] = Field(default=None, description="Parent Process ID")
    parent_process: Optional[str] = Field(default=None, description="Parent process executable basename")
    process_path: Optional[str] = Field(default=None, description="Full filesystem path of process executable")
    user_domain: Optional[str] = Field(default=None, description="Domain prefix stripped from domain-qualified user")
    tags: List[str] = Field(default_factory=list, description="Analyst or pipeline categorization tags")
    source_fields: Dict[str, Any] = Field(default_factory=dict, description="Source-specific fields isolated from top-level schema")


class NormalizedSecurityEvent(BaseModel):
    """
    Authoritative Normalized Security Event Model (v0.2.0).
    Consists of 10 required fields and 10 optional fields.
    """
    # Required Fields (10)
    event_id: str = Field(description="UUID v4 globally unique record ID assigned by AutoSOC")
    ingestion_id: str = Field(description="UUID v4 delivery attempt ID assigned by ingestion")
    timestamp: str = Field(description="ISO 8601 UTC observation timestamp (YYYY-MM-DDTHH:MM:SS.sssZ)")
    source: SourceTypeEnum = Field(description="Normalized telemetry source identifier")
    event_category: EventCategoryEnum = Field(description="High-level category enum")
    event_type: str = Field(description="Detailed event type dot-notation (e.g. process.create, network.dns)")
    host: str = Field(description="Originating host FQDN or sensor identifier (non-empty)")
    severity: int = Field(ge=1, le=5, description="Normalized severity integer (1=Info, 2=Low, 3=Med, 4=High, 5=Crit)")
    raw_event: str = Field(description="Original unparsed raw payload string preserved for forensics")
    metadata: Dict[str, Any] = Field(description="Structured metadata and source_fields container")

    # Optional Fields (10) - Default to None when absent
    user: Optional[str] = Field(default=None, description="Normalized username (lowercase, domain stripped)")
    source_ip: Optional[str] = Field(default=None, description="Initiating IPv4 or IPv6 address")
    destination_ip: Optional[str] = Field(default=None, description="Target IPv4 or IPv6 address")
    source_port: Optional[int] = Field(default=None, ge=0, le=65535, description="TCP/UDP source port")
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535, description="TCP/UDP destination port")
    protocol: Optional[ProtocolEnum] = Field(default=None, description="Normalized application/transport protocol")
    process: Optional[str] = Field(default=None, description="Executable basename (no path)")
    file_hash: Optional[str] = Field(default=None, description="Primary cryptographic hash (sha256:hex preferred)")
    domain: Optional[str] = Field(default=None, description="FQDN queried or contacted (lowercase, no trailing dot)")
    command_line: Optional[str] = Field(default=None, description="Full process invocation command string with sensitive args redacted")


class CategoricalFeatures(BaseModel):
    event_type: str
    event_category: str
    source: str
    protocol: Optional[str] = None
    severity: int
    is_internal_src: Optional[bool] = None
    is_internal_dst: Optional[bool] = None


class NetworkFeatures(BaseModel):
    src_ip_private: Optional[bool] = None
    dst_ip_private: Optional[bool] = None
    dst_port_well_known: Optional[bool] = None
    dst_port_suspicious: Optional[bool] = None
    geo_country_src: Optional[str] = None
    geo_country_dst: Optional[str] = None
    is_external_to_internal: Optional[bool] = None


class ProcessFeatures(BaseModel):
    process_name: Optional[str] = None
    has_encoded_command: Optional[bool] = None
    command_line_length: Optional[int] = None
    parent_child_suspicious: Optional[bool] = None
    is_lolbin: Optional[bool] = None


class FileFeatures(BaseModel):
    has_hash: Optional[bool] = None
    hash_known_malware: Optional[bool] = None
    file_extension: Optional[str] = None


class DnsFeatures(BaseModel):
    domain_length: Optional[int] = None
    subdomain_count: Optional[int] = None
    tld: Optional[str] = None
    domain_entropy: Optional[float] = None


class TemporalFeatures(BaseModel):
    hour_of_day: Optional[int] = None
    day_of_week: Optional[int] = None
    is_business_hours: Optional[bool] = None


class EventFeatures(BaseModel):
    """Derived feature representation extracted from validated normalized event for detection."""
    categorical: CategoricalFeatures
    network: NetworkFeatures
    process: ProcessFeatures
    file: FileFeatures
    dns: DnsFeatures
    temporal: TemporalFeatures
