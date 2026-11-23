"""
AutoSOC - Security Data Contract and Schema Consistency Tests

Deterministic test suite verifying schema invariants, required/optional fields,
enum memberships, identifier distinctions, protocol signatures, and canonical
fixtures from docs/security/security-event-model.md and docs/security/security-data-contract.md.
"""

import unittest
import sys
from pathlib import Path

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from typing import Dict, Any, Tuple, Optional, List

from app.events.schemas import (
    SourceTypeEnum,
    EventCategoryEnum,
    ProtocolEnum,
    IngestionEnvelope,
    ParsedEvent,
    EventMetadata,
    NormalizedSecurityEvent,
    EventFeatures,
    CategoricalFeatures,
    NetworkFeatures,
    ProcessFeatures,
    FileFeatures,
    DnsFeatures,
    TemporalFeatures,
)
from app.events.protocols import (
    SourceParserProtocol,
    EventNormalizerProtocol,
    EventValidatorProtocol,
    FeatureExtractorProtocol,
    DetectionEngineProtocol,
    AlertGeneratorProtocol,
)
from app.detection.schemas import (
    DetectorTypeEnum,
    AlertStatusEnum,
    EvidenceItem,
    SourceEventRef,
    DetectionResult,
    Alert,
)


class TestSecurityDataContractInvariants(unittest.TestCase):
    """Verifies schema invariants and field partitioning for NormalizedSecurityEvent."""

    def setUp(self):
        self.required_field_names = {
            "event_id",
            "ingestion_id",
            "timestamp",
            "source",
            "event_category",
            "event_type",
            "host",
            "severity",
            "raw_event",
            "metadata",
        }
        self.optional_field_names = {
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
        }

    def test_schema_field_partitioning(self):
        """NormalizedSecurityEvent must possess exactly 10 required and 10 optional fields."""
        annotations = getattr(NormalizedSecurityEvent, "__annotations__", {})
        total_fields = set(annotations.keys())
        expected_fields = self.required_field_names | self.optional_field_names

        self.assertEqual(
            total_fields,
            expected_fields,
            f"Field set mismatch: diff={total_fields.symmetric_difference(expected_fields)}",
        )
        self.assertEqual(len(self.required_field_names), 10)
        self.assertEqual(len(self.optional_field_names), 10)
        self.assertEqual(len(total_fields), 20)

    def test_required_fields_enforcement(self):
        """Omitting any required field must raise a validation/value error."""
        base_valid_data = {
            "event_id": "f2a3e881-0b1c-4f7d-9a2e-deadbeef0001",
            "ingestion_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
            "timestamp": "2026-09-21T06:42:17.334Z",
            "source": SourceTypeEnum.SYSMON,
            "event_category": EventCategoryEnum.PROCESS,
            "event_type": "process.create",
            "host": "workstation-07.corp.local",
            "severity": 1,
            "raw_event": "<Event>test</Event>",
            "metadata": {},
        }

        # Instantiation with all required fields succeeds
        event = NormalizedSecurityEvent(**base_valid_data)
        self.assertEqual(event.event_id, "f2a3e881-0b1c-4f7d-9a2e-deadbeef0001")
        self.assertEqual(event.severity, 1)

        # Omitting each required field individually must raise an exception
        for req_field in self.required_field_names:
            incomplete_data = dict(base_valid_data)
            del incomplete_data[req_field]
            with self.assertRaises((ValueError, TypeError), msg=f"Should fail when missing {req_field}"):
                NormalizedSecurityEvent(**incomplete_data)

    def test_optional_fields_default_to_none(self):
        """All 10 optional fields must default to None when omitted."""
        event = NormalizedSecurityEvent(
            event_id="f2a3e881-0b1c-4f7d-9a2e-deadbeef0001",
            ingestion_id="a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
            timestamp="2026-09-21T06:42:17.334Z",
            source=SourceTypeEnum.SYSMON,
            event_category=EventCategoryEnum.PROCESS,
            event_type="process.create",
            host="workstation-07.corp.local",
            severity=1,
            raw_event="<Event>test</Event>",
            metadata={},
        )
        for opt_field in self.optional_field_names:
            self.assertIsNone(
                getattr(event, opt_field),
                f"Optional field {opt_field} should default to None",
            )

    def test_severity_bounds(self):
        """Severity must be an integer constrained to range [1, 5]."""
        base_valid_data = {
            "event_id": "f2a3e881-0b1c-4f7d-9a2e-deadbeef0001",
            "ingestion_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
            "timestamp": "2026-09-21T06:42:17.334Z",
            "source": SourceTypeEnum.SYSMON,
            "event_category": EventCategoryEnum.PROCESS,
            "event_type": "process.create",
            "host": "workstation-07.corp.local",
            "raw_event": "<Event>test</Event>",
            "metadata": {},
        }

        # Valid bounds 1 through 5
        for s in (1, 2, 3, 4, 5):
            e = NormalizedSecurityEvent(severity=s, **base_valid_data)
            self.assertEqual(e.severity, s)

        # Invalid bounds < 1 or > 5
        with self.assertRaises(ValueError):
            NormalizedSecurityEvent(severity=0, **base_valid_data)
        with self.assertRaises(ValueError):
            NormalizedSecurityEvent(severity=6, **base_valid_data)

    def test_port_bounds(self):
        """Port fields must be constrained to [0, 65535]."""
        base_valid_data = {
            "event_id": "f2a3e881-0b1c-4f7d-9a2e-deadbeef0001",
            "ingestion_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
            "timestamp": "2026-09-21T06:42:17.334Z",
            "source": SourceTypeEnum.ZEEK,
            "event_category": EventCategoryEnum.NETWORK,
            "event_type": "network.connection",
            "host": "sensor-01",
            "severity": 1,
            "raw_event": "raw",
            "metadata": {},
        }

        # Valid boundary ports
        e1 = NormalizedSecurityEvent(source_port=0, destination_port=65535, **base_valid_data)
        self.assertEqual(e1.source_port, 0)
        self.assertEqual(e1.destination_port, 65535)

        # Invalid negative or out-of-range port
        with self.assertRaises(ValueError):
            NormalizedSecurityEvent(source_port=-1, **base_valid_data)
        with self.assertRaises(ValueError):
            NormalizedSecurityEvent(destination_port=65536, **base_valid_data)


class TestEnumerationContracts(unittest.TestCase):
    """Verifies that enum members strictly match the architecture specifications."""

    def test_source_type_enum_members(self):
        expected_sources = {
            "sysmon",
            "zeek",
            "suricata",
            "windows_event_log",
            "auditd",
            "osquery",
            "custom",
        }
        actual_sources = {m.value for m in SourceTypeEnum}
        self.assertEqual(actual_sources, expected_sources)

    def test_event_category_enum_members(self):
        expected_categories = {
            "process",
            "network",
            "file",
            "registry",
            "auth",
            "alert",
            "unknown",
        }
        actual_categories = {m.value for m in EventCategoryEnum}
        self.assertEqual(actual_categories, expected_categories)

    def test_protocol_enum_members(self):
        expected_protocols = {
            "tcp",
            "udp",
            "icmp",
            "dns",
            "http",
            "tls",
            "smtp",
            "ftp",
            "ssh",
            "rdp",
            "smb",
            "other",
        }
        actual_protocols = {m.value for m in ProtocolEnum}
        self.assertEqual(actual_protocols, expected_protocols)

    def test_detector_type_enum_members(self):
        expected_detectors = {
            "rule_sigma",
            "ml_classification",
            "ml_anomaly",
            "correlation",
            "threat_intel",
        }
        actual_detectors = {m.value for m in DetectorTypeEnum}
        self.assertEqual(actual_detectors, expected_detectors)

    def test_alert_status_enum_members(self):
        expected_statuses = {"open", "acknowledged", "closed", "false_positive"}
        actual_statuses = {m.value for m in AlertStatusEnum}
        self.assertEqual(actual_statuses, expected_statuses)


class TestIdentifierDistinctions(unittest.TestCase):
    """
    Verifies that the five core identifiers maintain distinct semantics
    and cannot be conflated in data contracts.
    """

    def test_distinct_identifier_semantics(self):
        event_id = "f2a3e881-0b1c-4f7d-9a2e-deadbeef0001"
        ingestion_id = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
        source_event_id = "Sysmon-Record-44120"
        raw_hash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        correlation_id = "corr-chain-99901"

        metadata = EventMetadata(
            ingest_time="2026-09-21T06:42:18.000Z",
            pipeline_version="0.2.0",
            raw_hash=raw_hash,
            source_event_id=source_event_id,
            correlation_id=correlation_id,
        )

        event = NormalizedSecurityEvent(
            event_id=event_id,
            ingestion_id=ingestion_id,
            timestamp="2026-09-21T06:42:17.334Z",
            source=SourceTypeEnum.SYSMON,
            event_category=EventCategoryEnum.PROCESS,
            event_type="process.create",
            host="workstation-07.corp.local",
            severity=1,
            raw_event="<Event>...</Event>",
            metadata=metadata.model_dump(),
        )

        # 1. event_id is top-level record ID
        self.assertEqual(event.event_id, event_id)
        # 2. ingestion_id is top-level delivery attempt ID
        self.assertEqual(event.ingestion_id, ingestion_id)
        self.assertNotEqual(event.event_id, event.ingestion_id)

        # 3. source_event_id is strictly located in metadata
        self.assertFalse(hasattr(event, "source_event_id"))
        self.assertEqual(event.metadata["source_event_id"], source_event_id)

        # 4. raw_hash is strictly located in metadata for deduplication
        self.assertFalse(hasattr(event, "raw_hash"))
        self.assertEqual(event.metadata["raw_hash"], raw_hash)

        # 5. correlation_id is strictly located in metadata for grouping
        self.assertFalse(hasattr(event, "correlation_id"))
        self.assertEqual(event.metadata["correlation_id"], correlation_id)


class TestCanonicalEventFixtures(unittest.TestCase):
    """
    Validates canonical event fixtures from docs/security/security-event-model.md §7
    against the authoritative NormalizedSecurityEvent schema.
    """

    def test_sysmon_process_create_canonical_fixture(self):
        """§7.1 Sysmon — Process Create (event_type: process.create)"""
        fixture = {
            "event_id": "f2a3e881-0b1c-4f7d-9a2e-deadbeef0001",
            "ingestion_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
            "timestamp": "2026-09-21T06:42:17.334Z",
            "source": "sysmon",
            "event_category": "process",
            "event_type": "process.create",
            "host": "workstation-07.corp.local",
            "user": "john.doe",
            "source_ip": None,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "protocol": None,
            "process": "powershell.exe",
            "file_hash": "sha256:aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344",
            "domain": None,
            "command_line": "powershell.exe -NonInteractive -EncodedCommand JABzAD0A...",
            "severity": 3,
            "raw_event": "<Event xmlns='...'><System>...</System><EventData>...</EventData></Event>",
            "metadata": {
                "ingest_time": "2026-09-21T06:42:18.001Z",
                "pipeline_version": "0.2.0",
                "raw_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "source_event_id": "82341",
                "source_severity": None,
                "raw_truncated": False,
                "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "parent_process": "cmd.exe",
                "parent_pid": 3100,
                "pid": 4288,
                "user_domain": "CORP",
                "hashes": {
                    "md5": "04029957f36c2f05b3b2cf77af3ae9d3",
                    "sha256": "aabbccdd...",
                },
                "mitre_techniques": ["T1059.001"],
                "tags": [],
            },
        }

        event = NormalizedSecurityEvent(**fixture)
        self.assertEqual(event.event_id, "f2a3e881-0b1c-4f7d-9a2e-deadbeef0001")
        self.assertEqual(event.event_category, EventCategoryEnum.PROCESS)
        self.assertEqual(event.process, "powershell.exe")
        self.assertEqual(event.severity, 3)

    def test_suricata_alert_canonical_fixture(self):
        """§7.2 Suricata — IDS Alert (event_type: alert.ids)"""
        fixture = {
            "event_id": "c9b1a762-3e4f-4a81-b0c2-deadbeef0002",
            "ingestion_id": "b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e",
            "timestamp": "2026-09-21T06:55:03.000Z",
            "source": "suricata",
            "event_category": "alert",
            "event_type": "alert.ids",
            "host": "sensor-lan01",
            "user": None,
            "source_ip": "192.168.1.45",
            "destination_ip": "185.220.101.34",
            "source_port": 54321,
            "destination_port": 443,
            "protocol": "tcp",
            "process": None,
            "file_hash": None,
            "domain": "malicious-c2.example.com",
            "command_line": None,
            "severity": 4,
            "raw_event": "{\"timestamp\":\"2026-09-21T06:55:03\",\"event_type\":\"alert\",...}",
            "metadata": {
                "ingest_time": "2026-09-21T06:55:03.500Z",
                "pipeline_version": "0.2.0",
                "raw_hash": "sha256:d41d8cd98f00b204e9800998ecf8427e00000000000000000000000000000000",
                "source_event_id": "flow_id:1234567890",
                "source_fields": {
                    "alert": {
                        "action": "allowed",
                        "gid": 1,
                        "signature_id": 2027865,
                        "rev": 3,
                        "signature": "ET MALWARE Potential C2 Domain",
                        "category": "Malware Command and Control Activity",
                    },
                    "app_proto": "tls",
                },
                "mitre_techniques": ["T1071.001"],
                "tags": [],
            },
        }

        event = NormalizedSecurityEvent(**fixture)
        self.assertEqual(event.event_id, "c9b1a762-3e4f-4a81-b0c2-deadbeef0002")
        self.assertEqual(event.event_category, EventCategoryEnum.ALERT)
        self.assertEqual(event.severity, 4)
        self.assertEqual(event.protocol, ProtocolEnum.TCP)

    def test_zeek_dns_query_canonical_fixture(self):
        """§7.3 Zeek — DNS Query (event_type: network.dns)"""
        fixture = {
            "event_id": "88fa1023-ccde-4b12-a997-deadbeef0003",
            "ingestion_id": "c3d4e5f6-a7b8-9c0d-1e2f-3a4b5c6d7e8f",
            "timestamp": "2026-09-21T07:01:44.812Z",
            "source": "zeek",
            "event_category": "network",
            "event_type": "network.dns",
            "host": "sensor-zeek01",
            "user": None,
            "source_ip": "10.0.0.55",
            "destination_ip": "8.8.8.8",
            "source_port": 53214,
            "destination_port": 53,
            "protocol": "udp",
            "process": None,
            "file_hash": None,
            "domain": "suspicious-domain.xyz",
            "command_line": None,
            "severity": 1,
            "raw_event": "{\"ts\":1758146504.812,\"uid\":\"Cl1Ab23Xyz...\",\"id.orig_h\":\"10.0.0.55\"}",
            "metadata": {
                "ingest_time": "2026-09-21T07:01:45.100Z",
                "pipeline_version": "0.2.0",
                "source_event_id": "Cl1Ab23Xyz...",
                "source_fields": {
                    "uid": "Cl1Ab23Xyz...",
                    "query": "suspicious-domain.xyz",
                    "qtype_name": "A",
                },
                "tags": [],
            },
        }

        event = NormalizedSecurityEvent(**fixture)
        self.assertEqual(event.event_id, "88fa1023-ccde-4b12-a997-deadbeef0003")
        self.assertEqual(event.event_category, EventCategoryEnum.NETWORK)
        self.assertEqual(event.domain, "suspicious-domain.xyz")
        self.assertEqual(event.protocol, ProtocolEnum.UDP)


class TestDetectionAndAlertContracts(unittest.TestCase):
    """Verifies schemas for DetectionResult, EvidenceItem, and Alert."""

    def test_detection_result_structure(self):
        source_ref = SourceEventRef(
            event_id="f2a3e881-0b1c-4f7d-9a2e-deadbeef0001",
            timestamp="2026-09-21T06:42:17.334Z",
            host="workstation-07.corp.local",
            event_type="process.create",
        )
        evidence = [
            EvidenceItem(
                field="command_line",
                value="powershell.exe -ExecutionPolicy Bypass",
                indicator="-ExecutionPolicy Bypass",
            )
        ]
        result = DetectionResult(
            detection_id="d1d2d3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
            created_at="2026-09-21T06:42:18.500Z",
            source_event_id="f2a3e881-0b1c-4f7d-9a2e-deadbeef0001",
            source_event_ref=source_ref,
            detector_type=DetectorTypeEnum.RULE_SIGMA,
            detector_id="sigma-win-powershell-bypass",
            detector_version="1.0.0",
            severity=4,
            confidence=1.0,
            matched_indicators=["-ExecutionPolicy Bypass"],
            evidence=evidence,
            mitre_tactics=["TA0002"],
            mitre_techniques=["T1059.001"],
            explanation="PowerShell invocation with execution policy bypass",
        )

        dumped = result.model_dump()
        self.assertEqual(dumped["detector_type"], "rule_sigma")
        self.assertEqual(dumped["severity"], 4)
        self.assertEqual(dumped["confidence"], 1.0)
        self.assertEqual(dumped["evidence"][0]["field"], "command_line")

    def test_alert_structure(self):
        alert = Alert(
            alert_id="a0a1a2a3-b4c5-d6e7-f8a9-b0c1d2e3f4a5",
            created_at="2026-09-21T06:42:19.000Z",
            rule_id="sigma-win-powershell-bypass",
            title="Suspicious ExecutionPolicy Bypass in PowerShell",
            description="PowerShell process executed with execution policy bypass flags",
            severity=4,
            mitre_tactics=["TA0002"],
            mitre_techniques=["T1059.001"],
            event_ids=["f2a3e881-0b1c-4f7d-9a2e-deadbeef0001"],
            host="workstation-07.corp.local",
            user="john.doe",
            status=AlertStatusEnum.OPEN,
            metadata={"dedup_count": 1},
        )
        dumped = alert.model_dump()
        self.assertEqual(dumped["status"], "open")
        self.assertEqual(dumped["severity"], 4)
        self.assertEqual(len(dumped["event_ids"]), 1)


class TestPipelineInterfaceProtocols(unittest.TestCase):
    """Verifies PEP 544 runtime-checkable protocol definitions."""

    def test_source_parser_protocol_conformance(self):
        class ValidParser:
            def parse(self, raw_payload: str, source_type: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
                return (True, {"raw": raw_payload}, None)

        class InvalidParser:
            def invalid_method(self):
                pass

        self.assertTrue(isinstance(ValidParser(), SourceParserProtocol))
        self.assertFalse(isinstance(InvalidParser(), SourceParserProtocol))

    def test_normalizer_protocol_conformance(self):
        class ValidNormalizer:
            def normalize(self, parsed_event: Dict[str, Any], ingestion_envelope: Dict[str, Any]) -> Dict[str, Any]:
                return {"event_id": "123"}

        class InvalidNormalizer:
            pass

        self.assertTrue(isinstance(ValidNormalizer(), EventNormalizerProtocol))
        self.assertFalse(isinstance(InvalidNormalizer(), EventNormalizerProtocol))

    def test_validator_protocol_conformance(self):
        class ValidValidator:
            async def validate(self, normalized_event: Dict[str, Any]) -> Tuple[str, List[str]]:
                return ("accepted", [])

        class InvalidValidator:
            pass

        self.assertTrue(isinstance(ValidValidator(), EventValidatorProtocol))
        self.assertFalse(isinstance(InvalidValidator(), EventValidatorProtocol))

    def test_feature_extractor_protocol_conformance(self):
        class ValidExtractor:
            def extract_features(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
                return {}

        class InvalidExtractor:
            pass

        self.assertTrue(isinstance(ValidExtractor(), FeatureExtractorProtocol))
        self.assertFalse(isinstance(InvalidExtractor(), FeatureExtractorProtocol))

    def test_detection_engine_protocol_conformance(self):
        class ValidEngine:
            async def evaluate(self, normalized_event: Dict[str, Any], features: Dict[str, Any]) -> List[Dict[str, Any]]:
                return []

        class InvalidEngine:
            pass

        self.assertTrue(isinstance(ValidEngine(), DetectionEngineProtocol))
        self.assertFalse(isinstance(InvalidEngine(), DetectionEngineProtocol))

    def test_alert_generator_protocol_conformance(self):
        class ValidAlertGen:
            async def process_detection(self, detection_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
                return None

        class InvalidAlertGen:
            pass

        self.assertTrue(isinstance(ValidAlertGen(), AlertGeneratorProtocol))
        self.assertFalse(isinstance(InvalidAlertGen(), AlertGeneratorProtocol))


if __name__ == "__main__":
    unittest.main()
