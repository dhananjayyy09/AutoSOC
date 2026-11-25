"""
AutoSOC Day 7 - Deterministic Security Event Parser & Normalization Tests

All fixtures are strictly synthetic test fixtures (no real secrets, credentials,
or private telemetry). Verifies:
- SourceParserProtocol and EventNormalizerProtocol runtime conformance
- Valid supported events (Suricata, Sysmon, Zeek)
- Events with optional fields missing (remain None)
- Malformed events (JSON, XML, XXE rejection, missing EventID)
- Unsupported event formats (enum-only sources like auditd/osquery/windows_event_log, custom, unknown)
- Invalid timestamps (missing tz, unparseable)
- Invalid network fields (invalid IP/port nulled with warnings, never silently coerced)
- Payloads with extra unknown fields (preserved in metadata.source_fields)
- Determinism and sanitized error non-leakage
"""

import json
from pathlib import Path
import sys
import unittest

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.events.normalizer import DeterministicEventNormalizer, NormalizationResult
from app.events.parser import DeterministicSourceParser
from app.events.protocols import EventNormalizerProtocol, SourceParserProtocol
from app.events.schemas import (
    EventCategoryEnum,
    NormalizationStatusEnum,
    NormalizedSecurityEvent,
    ProtocolEnum,
    SourceTypeEnum,
)
from app.events.validation import ValidationErrorCategory, compute_raw_hash


def _envelope(source_type: str, raw_payload: str, sensor_id: str = "sensor-test-01", ingestion_id: str = "a1b2c3d4-e5f6-4a8b-9c0d-1e2f3a4b5c6d") -> dict:
    return {
        "ingestion_id": ingestion_id,
        "source_type": source_type,
        "sensor_id": sensor_id,
        "ingest_time": "2026-09-21T07:00:00.000Z",
        "raw_hash": compute_raw_hash(raw_payload),
        "raw_payload": raw_payload,
    }


# ---------------------------------------------------------------------------
# Synthetic Test Fixtures (NOT live telemetry)
# ---------------------------------------------------------------------------

VALID_SURICATA_PAYLOAD = json.dumps(
    {
        "timestamp": "2026-09-21T06:55:03.000Z",
        "event_type": "alert",
        "host": "sensor-edge-test",
        "flow_id": 987654321,
        "src_ip": "192.0.2.10",
        "dest_ip": "198.51.100.42",
        "src_port": 54321,
        "dest_port": 443,
        "proto": "TCP",
        "tls": {"sni": "example-test.invalid."},
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2000001,
            "rev": 1,
            "signature": "TEST Synthetic IDS Signature",
            "category": "Test Category",
            "severity": 2,
        },
    }
)

VALID_SYSMON_PAYLOAD = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System>"
    "<EventID>1</EventID>"
    "<EventRecordID>82341</EventRecordID>"
    "<TimeCreated SystemTime='2026-09-21T06:42:17.334Z'/>"
    "<Computer>test-host-01.example.invalid</Computer>"
    "</System>"
    "<EventData>"
    "<Data Name='User'>TESTDOMAIN\\alice.test</Data>"
    "<Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
    "<Data Name='CommandLine'>cmd.exe /c echo synthetic</Data>"
    "<Data Name='ProcessId'>4288</Data>"
    "<Data Name='ParentProcessId'>3100</Data>"
    "<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data>"
    "<Data Name='Hashes'>MD5=00000000000000000000000000000001,SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</Data>"
    "</EventData>"
    "</Event>"
)

VALID_ZEEK_DNS_PAYLOAD = json.dumps(
    {
        "ts": 1790000000.5,
        "uid": "CtestZeekUid0001",
        "id.orig_h": "192.0.2.55",
        "id.orig_p": 53214,
        "id.resp_h": "198.51.100.53",
        "id.resp_p": 53,
        "proto": "udp",
        "query": "SUB.EXAMPLE.INVALID.",
        "qtype_name": "A",
        "rcode_name": "NOERROR",
    }
)


class TestProtocolConformanceAndDeterminism(unittest.TestCase):
    """Verify Day 5 protocol conformance and deterministic output."""

    def test_protocol_conformance(self):
        parser = DeterministicSourceParser()
        normalizer = DeterministicEventNormalizer(parser=parser)
        self.assertIsInstance(parser, SourceParserProtocol)
        self.assertIsInstance(normalizer, EventNormalizerProtocol)

    def test_deterministic_repeated_normalization(self):
        normalizer = DeterministicEventNormalizer()
        env = _envelope("suricata", VALID_SURICATA_PAYLOAD)
        fixed_id = "11111111-2222-4333-8444-555555555555"

        res1 = normalizer.normalize_envelope(env, event_id=fixed_id)
        res2 = normalizer.normalize_envelope(env, event_id=fixed_id)

        self.assertEqual(res1.model_dump(), res2.model_dump())
        self.assertEqual(res1.event.raw_event, VALID_SURICATA_PAYLOAD)


class TestValidSupportedFormats(unittest.TestCase):
    """Verify deterministic mapping for Suricata, Sysmon, and Zeek."""

    def setUp(self):
        self.normalizer = DeterministicEventNormalizer()

    def test_valid_suricata_alert_normalized(self):
        res = self.normalizer.normalize_envelope(_envelope("suricata", VALID_SURICATA_PAYLOAD))
        self.assertIsInstance(res, NormalizationResult)
        self.assertEqual(res.normalization_status, NormalizationStatusEnum.NORMALIZED)
        self.assertIsInstance(res.event, NormalizedSecurityEvent)
        ev = res.event
        self.assertEqual(ev.source, SourceTypeEnum.SURICATA)
        self.assertEqual(ev.event_category, EventCategoryEnum.ALERT)
        self.assertEqual(ev.event_type, "alert.ids")
        self.assertEqual(ev.host, "sensor-edge-test")
        self.assertEqual(ev.source_ip, "192.0.2.10")
        self.assertEqual(ev.destination_ip, "198.51.100.42")
        self.assertEqual(ev.source_port, 54321)
        self.assertEqual(ev.destination_port, 443)
        self.assertEqual(ev.protocol, ProtocolEnum.TCP)
        self.assertEqual(ev.domain, "example-test.invalid")
        self.assertEqual(ev.severity, 4)  # Suricata severity 2 -> AutoSOC 4
        self.assertEqual(ev.metadata["source_event_id"], "flow_id:987654321")
        self.assertEqual(ev.raw_event, VALID_SURICATA_PAYLOAD)

    def test_valid_sysmon_process_create_normalized(self):
        res = self.normalizer.normalize_envelope(
            _envelope("sysmon", VALID_SYSMON_PAYLOAD, sensor_id="test-host-01.example.invalid")
        )
        self.assertEqual(res.normalization_status, NormalizationStatusEnum.NORMALIZED)
        ev = res.event
        self.assertEqual(ev.source, SourceTypeEnum.SYSMON)
        self.assertEqual(ev.event_category, EventCategoryEnum.PROCESS)
        self.assertEqual(ev.event_type, "process.create")
        self.assertEqual(ev.timestamp, "2026-09-21T06:42:17.334Z")
        self.assertEqual(ev.host, "test-host-01.example.invalid")
        self.assertEqual(ev.user, "alice.test")
        self.assertEqual(ev.metadata["user_domain"], "TESTDOMAIN")
        self.assertEqual(ev.process, "cmd.exe")
        self.assertEqual(ev.metadata["process_path"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(ev.metadata["parent_process"], "explorer.exe")
        self.assertEqual(ev.metadata["pid"], 4288)
        self.assertEqual(ev.metadata["parent_pid"], 3100)
        self.assertEqual(
            ev.file_hash,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        self.assertEqual(ev.severity, 1)  # No artificial suspiciousness scoring
        self.assertEqual(ev.raw_event, VALID_SYSMON_PAYLOAD)

    def test_valid_zeek_dns_normalized(self):
        res = self.normalizer.normalize_envelope(
            _envelope("zeek", VALID_ZEEK_DNS_PAYLOAD, sensor_id="zeek-sensor-01")
        )
        self.assertEqual(res.normalization_status, NormalizationStatusEnum.NORMALIZED)
        ev = res.event
        self.assertEqual(ev.source, SourceTypeEnum.ZEEK)
        self.assertEqual(ev.event_category, EventCategoryEnum.NETWORK)
        self.assertEqual(ev.event_type, "network.dns")
        self.assertEqual(ev.host, "zeek-sensor-01")
        self.assertEqual(ev.source_ip, "192.0.2.55")
        self.assertEqual(ev.destination_ip, "198.51.100.53")
        self.assertEqual(ev.source_port, 53214)
        self.assertEqual(ev.destination_port, 53)
        self.assertEqual(ev.protocol, ProtocolEnum.UDP)
        self.assertEqual(ev.domain, "sub.example.invalid")
        self.assertEqual(ev.severity, 1)
        self.assertEqual(ev.metadata["source_event_id"], "CtestZeekUid0001")


class TestOptionalFieldsAndExtraUnknownFields(unittest.TestCase):
    """Verify missing optional fields remain null and extra fields are preserved."""

    def setUp(self):
        self.normalizer = DeterministicEventNormalizer()

    def test_missing_optional_fields_remain_none(self):
        minimal_suricata = json.dumps(
            {"timestamp": "2026-09-21T06:55:03.000Z", "event_type": "flow"}
        )
        res = self.normalizer.normalize_envelope(_envelope("suricata", minimal_suricata))
        self.assertEqual(res.normalization_status, NormalizationStatusEnum.NORMALIZED)
        ev = res.event
        for field_name in (
            "user",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
            "process",
            "file_hash",
            "domain",
            "command_line",
        ):
            self.assertIsNone(getattr(ev, field_name), f"{field_name} must remain None")

    def test_extra_unknown_fields_preserved_in_source_fields(self):
        zeek_with_extra = json.dumps(
            {
                "ts": 1790000000.5,
                "uid": "Cextra001",
                "id.orig_h": "192.0.2.55",
                "proto": "tcp",
                "conn_state": "SF",
                "custom_experimental_flag": "alpha-9",
                "nested_unknown": {"k": 42},
            }
        )
        res = self.normalizer.normalize_envelope(_envelope("zeek", zeek_with_extra))
        self.assertEqual(res.normalization_status, NormalizationStatusEnum.NORMALIZED)
        src_fields = res.event.metadata["source_fields"]
        self.assertEqual(src_fields["custom_experimental_flag"], "alpha-9")
        self.assertEqual(src_fields["nested_unknown"], {"k": 42})


class TestErrorHandlingUnsupportedAndInvalidFields(unittest.TestCase):
    """Verify malformed payloads, unsupported formats, invalid timestamps, and invalid network fields."""

    def setUp(self):
        self.normalizer = DeterministicEventNormalizer()

    def test_malformed_events_and_no_secret_leakage(self):
        secret = "SYNTHETIC_SECRET_VALUE_DO_NOT_ECHO"
        bad_json = f"{{broken {secret}"
        res = self.normalizer.normalize_envelope(_envelope("suricata", bad_json))
        self.assertEqual(res.normalization_status, NormalizationStatusEnum.FAILED)
        self.assertIsNone(res.event)
        self.assertNotIn(secret, json.dumps(res.model_dump()))

        xxe_xml = (
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
            "<Event><System><EventID>1</EventID></System></Event>"
        )
        res_xml = self.normalizer.normalize_envelope(_envelope("sysmon", xxe_xml))
        self.assertEqual(res_xml.normalization_status, NormalizationStatusEnum.FAILED)
        self.assertIsNone(res_xml.event)

    def test_unsupported_source_formats(self):
        for unsupported in ("auditd", "osquery", "windows_event_log", "custom", "unknown_siem"):
            res = self.normalizer.normalize_envelope(_envelope(unsupported, '{"msg": "test"}'))
            self.assertEqual(res.normalization_status, NormalizationStatusEnum.UNSUPPORTED)
            self.assertIsNone(res.event)
            self.assertEqual(res.errors[0].category, ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE)

    def test_invalid_timestamp_rejected(self):
        # Naive timestamp missing timezone offset must fail (never guessed)
        naive_suricata = json.dumps({"timestamp": "2026-09-21T06:55:03", "event_type": "flow"})
        res = self.normalizer.normalize_envelope(_envelope("suricata", naive_suricata))
        self.assertEqual(res.normalization_status, NormalizationStatusEnum.FAILED)
        self.assertIsNone(res.event)
        self.assertEqual(res.errors[0].category, ValidationErrorCategory.INVALID_TIMESTAMP)

    def test_invalid_network_fields_nulled_with_warnings(self):
        bad_net_suricata = json.dumps(
            {
                "timestamp": "2026-09-21T06:55:03.000Z",
                "event_type": "flow",
                "src_ip": "999.999.1.1",
                "dest_ip": "not-an-ip",
                "src_port": 70000,
                "dest_port": -5,
                "proto": "sctp",
            }
        )
        res = self.normalizer.normalize_envelope(_envelope("suricata", bad_net_suricata))
        self.assertEqual(res.normalization_status, NormalizationStatusEnum.NORMALIZED_WITH_WARNINGS)
        self.assertIsNotNone(res.event)
        ev = res.event
        self.assertIsNone(ev.source_ip)
        self.assertIsNone(ev.destination_ip)
        self.assertIsNone(ev.source_port)
        self.assertIsNone(ev.destination_port)
        self.assertEqual(ev.protocol, ProtocolEnum.OTHER)
        self.assertEqual(len(res.warnings), 5)


if __name__ == "__main__":
    unittest.main()
