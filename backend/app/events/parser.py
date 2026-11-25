"""
AutoSOC - Deterministic Security Event Source Parser (Day 7)

Implements SourceParserProtocol for explicitly supported Day 7 telemetry formats:
- suricata (EVE JSON)
- sysmon (Windows Event XML)
- zeek (Zeek JSON)

Stateless, deterministic, no LLM usage, no network/DB calls, and sanitized errors.
"""

import json
import re
from typing import Any, Dict, Optional, Tuple
import xml.etree.ElementTree as ET

SUPPORTED_PARSER_SOURCES = frozenset({"suricata", "sysmon", "zeek"})

_XML_UNSAFE_PATTERN = re.compile(r"<!(?:DOCTYPE|ENTITY)", re.IGNORECASE)


def _strip_xml_ns(tag: str) -> str:
    """Strip XML namespace URI prefix from an ElementTree tag."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _parse_suricata_json(raw_payload: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    try:
        parsed = json.loads(raw_payload.strip())
    except json.JSONDecodeError:
        return False, None, "Malformed Suricata EVE JSON payload"

    if not isinstance(parsed, dict):
        return False, None, "Suricata payload must be a JSON object"

    return True, parsed, None


def _parse_zeek_json(raw_payload: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    stripped = raw_payload.strip()
    if not stripped.startswith("{"):
        return (
            False,
            None,
            "Unsupported Zeek payload format; Day 7 parser supports Zeek JSON objects only",
        )
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return False, None, "Malformed Zeek JSON payload"

    if not isinstance(parsed, dict):
        return False, None, "Zeek payload must be a JSON object"

    return True, parsed, None


def _parse_sysmon_xml(raw_payload: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    stripped = raw_payload.strip()
    if _XML_UNSAFE_PATTERN.search(stripped):
        return False, None, "Sysmon XML contains disallowed DOCTYPE or ENTITY declaration"

    try:
        root = ET.fromstring(stripped)
    except ET.ParseError:
        return False, None, "Malformed Sysmon XML payload"

    if _strip_xml_ns(root.tag) != "Event":
        return False, None, "Sysmon XML root element must be 'Event'"

    system_el = None
    event_data_el = None
    for child in root:
        name = _strip_xml_ns(child.tag)
        if name == "System":
            system_el = child
        elif name == "EventData":
            event_data_el = child

    if system_el is None:
        return False, None, "Sysmon XML missing required 'System' element"

    parsed: Dict[str, Any] = {"EventData": {}}
    for child in system_el:
        name = _strip_xml_ns(child.tag)
        if name == "TimeCreated":
            parsed["TimeCreated"] = child.attrib.get("SystemTime") or (child.text or "").strip() or None
        elif name in ("EventID", "EventRecordID", "Computer", "Channel", "Level"):
            parsed[name] = (child.text or "").strip() if child.text else None

    if not parsed.get("EventID"):
        return False, None, "Sysmon XML missing required 'System.EventID' element"

    if event_data_el is not None:
        for data_el in event_data_el:
            if _strip_xml_ns(data_el.tag) == "Data":
                key = data_el.attrib.get("Name")
                if key:
                    parsed["EventData"][key] = data_el.text if data_el.text is not None else ""

    return True, parsed, None


class DeterministicSourceParser:
    """
    Stateless pure-function parser implementing SourceParserProtocol.
    Converts raw payloads for supported formats into source-native dictionaries.
    """

    def parse(
        self, raw_payload: str, source_type: str
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        if not isinstance(raw_payload, str) or not raw_payload.strip():
            return False, None, "raw_payload must be a non-empty string"

        if not isinstance(source_type, str) or source_type not in SUPPORTED_PARSER_SOURCES:
            return (
                False,
                None,
                f"Source type '{source_type}' is not supported by Day 7 deterministic parser",
            )

        if source_type == "suricata":
            return _parse_suricata_json(raw_payload)
        if source_type == "sysmon":
            return _parse_sysmon_xml(raw_payload)
        return _parse_zeek_json(raw_payload)
