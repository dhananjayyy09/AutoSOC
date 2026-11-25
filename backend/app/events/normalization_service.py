"""
AutoSOC - Deterministic Security Event Normalization Service (Day 7)

Coordinates retrieval of an accepted RawEventEnvelope, deterministic parsing
(SourceParserProtocol), normalization (EventNormalizerProtocol), contract
validation against NormalizedSecurityEvent (plus optional EventValidatorProtocol),
and persistence of the NormalizedEvent record without mutating or deleting
the immutable raw source evidence.
"""

import json
import logging
import re
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.events.models import NormalizedEvent, RawEventEnvelope
from app.events.protocols import (
    EventNormalizerProtocol,
    EventValidatorProtocol,
    SourceParserProtocol,
)
from app.events.repository import (
    get_normalized_event_by_ingestion_id,
    get_raw_envelope_by_ingestion_id,
    persist_normalized_event,
)
from app.events.schemas import (
    EventCategoryEnum,
    NormalizedSecurityEvent,
    ProtocolEnum,
    SourceTypeEnum,
)

logger = logging.getLogger("autosoc")

_UNSUPPORTED_NORMALIZATION_SOURCES = {SourceTypeEnum.CUSTOM.value}
_XML_UNSAFE_PATTERN = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


def _strip_xml_ns(tag: str) -> str:
    """Remove XML namespace prefix from an ElementTree tag."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


class BasicSourceParser:
    """
    Deterministic baseline SourceParserProtocol implementation for Day 7.
    Extracts source-native fields without inventing values or mutating raw data.
    Intended to be swapped with Pranjal's full source-adapter parsers when integrated.
    """

    def parse(
        self, raw_payload: str, source_type: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        if source_type in _UNSUPPORTED_NORMALIZATION_SOURCES:
            return False, None, f"Unsupported source_type for normalization: '{source_type}'"

        stripped = raw_payload.strip()
        if not stripped:
            return False, None, "raw_payload is empty"

        if source_type in (SourceTypeEnum.SURICATA.value, SourceTypeEnum.ZEEK.value):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                return False, None, f"Malformed JSON payload for source_type '{source_type}'"
            if not isinstance(parsed, dict):
                return False, None, f"Expected JSON object for source_type '{source_type}'"
            return True, parsed, None

        if source_type == SourceTypeEnum.SYSMON.value:
            if _XML_UNSAFE_PATTERN.search(stripped):
                return False, None, "XML DOCTYPE/ENTITY declarations are not permitted"
            try:
                root = ET.fromstring(stripped)
            except ET.ParseError:
                return False, None, "Malformed XML payload for source_type 'sysmon'"

            fields: Dict[str, Any] = {}
            for elem in root.iter():
                local = _strip_xml_ns(elem.tag)
                if local == "EventID" and elem.text and elem.text.strip():
                    fields["EventID"] = elem.text.strip()
                elif local == "Computer" and elem.text and elem.text.strip():
                    fields["Computer"] = elem.text.strip()
                elif local == "TimeCreated" and elem.attrib.get("SystemTime"):
                    fields["TimeCreated"] = elem.attrib["SystemTime"].strip()
                elif local == "Data" and elem.attrib.get("Name"):
                    name = elem.attrib["Name"].strip()
                    if elem.text is not None:
                        fields[name] = elem.text.strip()
            return True, fields, None

        return False, None, f"No deterministic parser configured for source_type '{source_type}'"


class BasicEventNormalizer:
    """
    Deterministic baseline EventNormalizerProtocol implementation for Day 7.
    Maps explicitly present source fields into NormalizedSecurityEvent format.
    Absent optional fields remain None; missing values are never invented.
    """

    def normalize(
        self, parsed_event: Dict[str, Any], ingestion_envelope: Dict[str, Any]
    ) -> Dict[str, Any]:
        source_type = str(ingestion_envelope["source_type"])
        event_id = str(uuid.uuid4())
        metadata: Dict[str, Any] = {
            "ingest_time": ingestion_envelope["ingest_time"],
            "pipeline_version": "0.2.0-day7",
            "raw_hash": ingestion_envelope["raw_hash"],
            "source_fields": dict(parsed_event),
        }

        normalized: Dict[str, Any] = {
            "event_id": event_id,
            "ingestion_id": ingestion_envelope["ingestion_id"],
            "source": source_type,
            "raw_event": ingestion_envelope["raw_payload"],
            "metadata": metadata,
            "user": None,
            "source_ip": None,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "protocol": None,
            "process": None,
            "file_hash": None,
            "domain": None,
            "command_line": None,
        }

        if source_type == SourceTypeEnum.SURICATA.value:
            raw_proto = parsed_event.get("proto")
            proto_val = _normalize_protocol(raw_proto)
            alert_obj = parsed_event.get("alert") if isinstance(parsed_event.get("alert"), dict) else {}
            raw_sev = parsed_event.get("severity")
            if raw_sev is None and isinstance(alert_obj.get("severity"), int):
                # Suricata alert.severity 1..4 -> AutoSOC 2..5 per security-data-contract §6.4
                raw_sev = min(5, max(1, alert_obj["severity"] + 1))

            event_type_raw = parsed_event.get("event_type")
            category, event_type = _map_suricata_type(event_type_raw)

            normalized.update(
                {
                    "timestamp": parsed_event.get("timestamp"),
                    "event_category": category,
                    "event_type": event_type,
                    "host": parsed_event.get("host") or ingestion_envelope.get("sensor_id"),
                    "severity": raw_sev,
                    "source_ip": parsed_event.get("src_ip"),
                    "destination_ip": parsed_event.get("dest_ip"),
                    "source_port": parsed_event.get("src_port"),
                    "destination_port": parsed_event.get("dest_port"),
                    "protocol": proto_val,
                }
            )
            if isinstance(parsed_event.get("flow_id"), (str, int)):
                metadata["source_event_id"] = f"flow_id:{parsed_event['flow_id']}"

        elif source_type == SourceTypeEnum.ZEEK.value:
            proto_val = _normalize_protocol(parsed_event.get("proto"))
            is_dns = "query" in parsed_event
            normalized.update(
                {
                    "timestamp": parsed_event.get("timestamp"),
                    "event_category": EventCategoryEnum.NETWORK.value,
                    "event_type": "network.dns" if is_dns else "network.connection",
                    "host": parsed_event.get("host") or ingestion_envelope.get("sensor_id"),
                    "severity": parsed_event.get("severity"),
                    "source_ip": parsed_event.get("id.orig_h"),
                    "destination_ip": parsed_event.get("id.resp_h"),
                    "source_port": parsed_event.get("id.orig_p"),
                    "destination_port": parsed_event.get("id.resp_p"),
                    "protocol": proto_val,
                    "domain": parsed_event.get("query").lower().rstrip(".")
                    if isinstance(parsed_event.get("query"), str)
                    else None,
                }
            )
            if isinstance(parsed_event.get("uid"), str):
                metadata["source_event_id"] = parsed_event["uid"]

        elif source_type == SourceTypeEnum.SYSMON.value:
            sysmon_id = str(parsed_event.get("EventID", ""))
            category, event_type = _map_sysmon_event_id(sysmon_id)
            image_val = parsed_event.get("Image")
            process_name = (
                image_val.replace("\\", "/").rsplit("/", 1)[-1]
                if isinstance(image_val, str) and image_val.strip()
                else None
            )
            user_val = parsed_event.get("User")
            if isinstance(user_val, str) and "\\" in user_val:
                domain_part, user_part = user_val.split("\\", 1)
                metadata["user_domain"] = domain_part
                user_val = user_part.lower()
            elif isinstance(user_val, str):
                user_val = user_val.lower()

            normalized.update(
                {
                    "timestamp": parsed_event.get("TimeCreated"),
                    "event_category": category,
                    "event_type": event_type,
                    "host": parsed_event.get("Computer"),
                    "severity": parsed_event.get("severity"),
                    "user": user_val,
                    "source_ip": parsed_event.get("SourceIp"),
                    "destination_ip": parsed_event.get("DestinationIp"),
                    "source_port": _to_int_or_none(parsed_event.get("SourcePort")),
                    "destination_port": _to_int_or_none(parsed_event.get("DestinationPort")),
                    "protocol": _normalize_protocol(parsed_event.get("Protocol")),
                    "process": process_name,
                    "domain": parsed_event.get("QueryName").lower().rstrip(".")
                    if isinstance(parsed_event.get("QueryName"), str)
                    else None,
                    "command_line": parsed_event.get("CommandLine"),
                }
            )

        return normalized


def _to_int_or_none(value: Any) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _normalize_protocol(raw_proto: Any) -> Optional[str]:
    if not isinstance(raw_proto, str) or not raw_proto.strip():
        return None
    lowered = raw_proto.strip().lower()
    try:
        return ProtocolEnum(lowered).value
    except ValueError:
        return ProtocolEnum.OTHER.value


def _map_suricata_type(event_type: Any) -> Tuple[Optional[str], Optional[str]]:
    if not isinstance(event_type, str) or not event_type.strip():
        return None, None
    lowered = event_type.strip().lower()
    if lowered == "alert":
        return EventCategoryEnum.ALERT.value, "alert.ids"
    if lowered in ("dns", "http", "tls", "flow"):
        return EventCategoryEnum.NETWORK.value, f"network.{lowered}"
    return EventCategoryEnum.UNKNOWN.value, "unknown"


def _map_sysmon_event_id(event_id: str) -> Tuple[Optional[str], Optional[str]]:
    mapping = {
        "1": (EventCategoryEnum.PROCESS.value, "process.create"),
        "3": (EventCategoryEnum.NETWORK.value, "network.connection"),
        "5": (EventCategoryEnum.PROCESS.value, "process.terminate"),
        "8": (EventCategoryEnum.PROCESS.value, "process.inject"),
        "11": (EventCategoryEnum.FILE.value, "file.create"),
        "12": (EventCategoryEnum.REGISTRY.value, "registry.create"),
        "13": (EventCategoryEnum.REGISTRY.value, "registry.modify"),
        "14": (EventCategoryEnum.REGISTRY.value, "registry.modify"),
        "22": (EventCategoryEnum.NETWORK.value, "network.dns"),
        "23": (EventCategoryEnum.FILE.value, "file.delete"),
    }
    return mapping.get(event_id, (None, None))


def _sanitize_validation_errors(exc: ValidationError) -> List[str]:
    messages: List[str] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ()))
        msg = err.get("msg", "Invalid value")
        messages.append(f"{loc}: {msg}" if loc else msg)
    return messages


class NormalizationService:
    """
    Application service orchestrating deterministic security-event normalization:
      1. Retrieve accepted raw event (when invoked by ingestion_id)
      2. Parse raw_payload via SourceParserProtocol
      3. Normalize parsed fields via EventNormalizerProtocol
      4. Validate against NormalizedSecurityEvent (+ optional EventValidatorProtocol)
      5. Persist NormalizedEvent outcome (success or failure) without altering RawEventEnvelope
    """

    def __init__(
        self,
        parser: Optional[SourceParserProtocol] = None,
        normalizer: Optional[EventNormalizerProtocol] = None,
        validator: Optional[EventValidatorProtocol] = None,
    ) -> None:
        self._parser: SourceParserProtocol = parser or BasicSourceParser()
        self._normalizer: EventNormalizerProtocol = normalizer or BasicEventNormalizer()
        self._validator: Optional[EventValidatorProtocol] = validator

    async def normalize_by_ingestion_id(
        self, session: AsyncSession, ingestion_id: str
    ) -> Optional[NormalizedEvent]:
        """Retrieve an accepted raw envelope by ingestion_id and normalize it."""
        raw_envelope = await get_raw_envelope_by_ingestion_id(session, ingestion_id)
        if raw_envelope is None:
            return None
        return await self.normalize_and_persist(session, raw_envelope)

    async def normalize_and_persist(
        self, session: AsyncSession, raw_envelope: RawEventEnvelope
    ) -> NormalizedEvent:
        """
        Deterministically normalize a persisted RawEventEnvelope and store the
        resulting NormalizedEvent record (or failure/unsupported outcome).
        Idempotent on `ingestion_id`: returns existing record if already normalized.
        """
        existing = await get_normalized_event_by_ingestion_id(
            session, raw_envelope.ingestion_id
        )
        if existing is not None:
            return existing

        # 1. Parse raw payload via SourceParserProtocol
        parse_ok, parsed_fields, parse_error = self._parser.parse(
            raw_envelope.raw_payload, raw_envelope.source_type
        )
        if not parse_ok or parsed_fields is None:
            is_unsupported = (
                raw_envelope.source_type in _UNSUPPORTED_NORMALIZATION_SOURCES
                or (parse_error is not None and "unsupported" in parse_error.lower())
            )
            status_val = "unsupported" if is_unsupported else "failed"
            failed_record = NormalizedEvent(
                event_id=None,
                raw_envelope_id=raw_envelope.id,
                ingestion_id=raw_envelope.ingestion_id,
                source_type=raw_envelope.source_type,
                sensor_id=raw_envelope.sensor_id,
                event_metadata={
                    "ingest_time": raw_envelope.ingest_time,
                    "raw_hash": raw_envelope.raw_hash,
                },
                normalization_status=status_val,
                normalization_errors=[parse_error or "Source parsing failed"],
                normalization_warnings=[],
            )
            return await persist_normalized_event(session, failed_record)

        # 2. Normalize parsed fields via EventNormalizerProtocol
        envelope_dict: Dict[str, Any] = {
            "ingestion_id": raw_envelope.ingestion_id,
            "source_type": raw_envelope.source_type,
            "sensor_id": raw_envelope.sensor_id,
            "ingest_time": raw_envelope.ingest_time,
            "raw_hash": raw_envelope.raw_hash,
            "raw_payload": raw_envelope.raw_payload,
        }
        try:
            normalized_dict = self._normalizer.normalize(parsed_fields, envelope_dict)
        except Exception as exc:
            logger.warning(
                "Normalizer raised %s for ingestion_id=%s",
                type(exc).__name__,
                raw_envelope.ingestion_id,
            )
            failed_record = NormalizedEvent(
                event_id=None,
                raw_envelope_id=raw_envelope.id,
                ingestion_id=raw_envelope.ingestion_id,
                source_type=raw_envelope.source_type,
                sensor_id=raw_envelope.sensor_id,
                event_metadata={
                    "ingest_time": raw_envelope.ingest_time,
                    "raw_hash": raw_envelope.raw_hash,
                },
                normalization_status="failed",
                normalization_errors=[f"Normalization error: {type(exc).__name__}"],
                normalization_warnings=[],
            )
            return await persist_normalized_event(session, failed_record)

        # 3. Validate normalized output against NormalizedSecurityEvent contract
        warnings: List[str] = []
        try:
            validated_model = NormalizedSecurityEvent(**normalized_dict)
        except ValidationError as exc:
            sanitized_errors = _sanitize_validation_errors(exc)
            failed_record = NormalizedEvent(
                event_id=None,
                raw_envelope_id=raw_envelope.id,
                ingestion_id=raw_envelope.ingestion_id,
                source_type=raw_envelope.source_type,
                sensor_id=raw_envelope.sensor_id,
                event_timestamp=normalized_dict.get("timestamp")
                if isinstance(normalized_dict.get("timestamp"), str)
                else None,
                event_category=normalized_dict.get("event_category")
                if isinstance(normalized_dict.get("event_category"), str)
                else None,
                event_type=normalized_dict.get("event_type")
                if isinstance(normalized_dict.get("event_type"), str)
                else None,
                host=normalized_dict.get("host")
                if isinstance(normalized_dict.get("host"), str)
                else None,
                event_metadata={
                    "ingest_time": raw_envelope.ingest_time,
                    "raw_hash": raw_envelope.raw_hash,
                },
                normalization_status="failed",
                normalization_errors=sanitized_errors,
                normalization_warnings=[],
            )
            return await persist_normalized_event(session, failed_record)

        dumped = validated_model.model_dump()

        # 4. Optional EventValidatorProtocol semantic check
        if self._validator is not None:
            disposition, val_messages = await self._validator.validate(dumped)
            if disposition in ("rejected", "unsupported"):
                failed_record = NormalizedEvent(
                    event_id=None,
                    raw_envelope_id=raw_envelope.id,
                    ingestion_id=raw_envelope.ingestion_id,
                    source_type=raw_envelope.source_type,
                    sensor_id=raw_envelope.sensor_id,
                    event_timestamp=dumped.get("timestamp"),
                    event_category=dumped.get("event_category"),
                    event_type=dumped.get("event_type"),
                    host=dumped.get("host"),
                    event_metadata=dumped.get("metadata", {}),
                    normalization_status="unsupported"
                    if disposition == "unsupported"
                    else "failed",
                    normalization_errors=list(val_messages),
                    normalization_warnings=[],
                )
                return await persist_normalized_event(session, failed_record)
            if disposition == "accepted_with_warnings":
                warnings.extend(val_messages)

        norm_status = "normalized_with_warnings" if warnings else "normalized"
        record = NormalizedEvent(
            event_id=dumped["event_id"],
            raw_envelope_id=raw_envelope.id,
            ingestion_id=raw_envelope.ingestion_id,
            event_timestamp=dumped["timestamp"],
            source_type=dumped["source"],
            sensor_id=raw_envelope.sensor_id,
            event_category=dumped["event_category"],
            event_type=dumped["event_type"],
            host=dumped["host"],
            user_name=dumped.get("user"),
            source_ip=dumped.get("source_ip"),
            destination_ip=dumped.get("destination_ip"),
            source_port=dumped.get("source_port"),
            destination_port=dumped.get("destination_port"),
            protocol=dumped.get("protocol"),
            process=dumped.get("process"),
            file_hash=dumped.get("file_hash"),
            domain=dumped.get("domain"),
            command_line=dumped.get("command_line"),
            severity=dumped["severity"],
            event_metadata=dumped["metadata"],
            normalization_status=norm_status,
            normalization_errors=[],
            normalization_warnings=warnings,
        )
        return await persist_normalized_event(session, record)
