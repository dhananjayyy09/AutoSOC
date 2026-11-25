"""
AutoSOC Day 6 - Ingestion Envelope Validation & Acceptance Tests

Deterministic test suite verifying:
- Canonical Sysmon, Suricata, and Zeek test fixtures (clearly marked as fixtures)
- Required field enforcement and invalid envelope rejection
- Timestamp, metadata, and identifier validation
- Unsupported source formats and malformed payload handling
- Sensitive payload non-leakage in validation errors
- Duplicate-event flagging behavior (raw_hash and ingestion_id)
- Regression compatibility with Day 5 IngestionEnvelope schema
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import unittest

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.events.schemas import IngestionEnvelope, SourceTypeEnum
from app.events.validation import (
    DuplicateTrackerProtocol,
    IngestionDisposition,
    IngestionEnvelopeValidator,
    InMemoryDuplicateTracker,
    MAX_RAW_PAYLOAD_BYTES,
    ValidationErrorCategory,
    compute_raw_hash,
    validate_event_metadata,
    validate_ingestion_envelope,
)


def _make_canonical_sysmon_fixture() -> dict:
    """Test fixture derived from docs/security/security-event-model.md §7.1 (NOT live telemetry)."""
    raw_payload = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System><EventID>1</EventID><Computer>workstation-07.corp.local</Computer></System>"
        "<EventData><Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
        "<Data Name='CommandLine'>powershell.exe -NonInteractive -EncodedCommand JABzAD0A</Data></EventData>"
        "</Event>"
    )
    return {
        "ingestion_id": "a1b2c3d4-e5f6-4a8b-9c0d-1e2f3a4b5c6d",
        "source_type": "sysmon",
        "sensor_id": "workstation-07.corp.local",
        "ingest_time": "2026-09-21T06:42:18.001Z",
        "raw_hash": compute_raw_hash(raw_payload),
        "raw_payload": raw_payload,
    }


def _make_canonical_suricata_fixture() -> dict:
    """Test fixture derived from docs/security/security-event-model.md §7.2 (NOT live telemetry)."""
    raw_payload = json.dumps(
        {
            "timestamp": "2026-09-21T06:55:03.000Z",
            "event_type": "alert",
            "src_ip": "192.168.1.45",
            "dest_ip": "185.220.101.34",
            "src_port": 54321,
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2027865,
                "rev": 3,
                "signature": "ET MALWARE Potential C2 Domain",
                "category": "Malware Command and Control Activity",
            },
        }
    )
    return {
        "ingestion_id": "b2c3d4e5-f6a7-4b9c-8d1e-2f3a4b5c6d7e",
        "source_type": "suricata",
        "sensor_id": "sensor-lan01",
        "ingest_time": "2026-09-21T06:55:03.500Z",
        "raw_hash": compute_raw_hash(raw_payload),
        "raw_payload": raw_payload,
    }


def _make_canonical_zeek_fixture() -> dict:
    """Test fixture derived from docs/security/security-event-model.md §7.3 (NOT live telemetry)."""
    raw_payload = json.dumps(
        {
            "ts": 1758146504.812,
            "uid": "Cl1Ab23Xyz0001",
            "id.orig_h": "10.0.0.55",
            "id.resp_h": "8.8.8.8",
            "id.orig_p": 53214,
            "id.resp_p": 53,
            "proto": "udp",
            "query": "suspicious-domain.xyz",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
        }
    )
    return {
        "ingestion_id": "c3d4e5f6-a7b8-4c0d-9e2f-3a4b5c6d7e8f",
        "source_type": "zeek",
        "sensor_id": "sensor-zeek01",
        "ingest_time": "2026-09-21T07:01:45.100Z",
        "raw_hash": compute_raw_hash(raw_payload),
        "raw_payload": raw_payload,
    }


class TestCanonicalIngestionFixtures(unittest.TestCase):
    """Verify canonical Sysmon, Suricata, and Zeek test fixtures pass validation."""

    def test_sysmon_fixture_accepted(self):
        fixture = _make_canonical_sysmon_fixture()
        result = validate_ingestion_envelope(fixture)
        self.assertTrue(result.valid)
        self.assertEqual(result.disposition, IngestionDisposition.ACCEPTED)
        self.assertIsInstance(result.envelope, IngestionEnvelope)
        self.assertEqual(result.envelope.source_type, SourceTypeEnum.SYSMON)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.warnings, [])

    def test_suricata_fixture_accepted(self):
        fixture = _make_canonical_suricata_fixture()
        result = validate_ingestion_envelope(fixture)
        self.assertTrue(result.valid)
        self.assertEqual(result.disposition, IngestionDisposition.ACCEPTED)
        self.assertIsInstance(result.envelope, IngestionEnvelope)
        self.assertEqual(result.envelope.source_type, SourceTypeEnum.SURICATA)
        self.assertEqual(result.errors, [])

    def test_zeek_fixture_accepted(self):
        fixture = _make_canonical_zeek_fixture()
        result = validate_ingestion_envelope(fixture)
        self.assertTrue(result.valid)
        self.assertEqual(result.disposition, IngestionDisposition.ACCEPTED)
        self.assertIsInstance(result.envelope, IngestionEnvelope)
        self.assertEqual(result.envelope.source_type, SourceTypeEnum.ZEEK)
        self.assertEqual(result.errors, [])

    def test_day5_envelope_regression_compatibility(self):
        """Validated envelope model_dump() matches Day 5 IngestionEnvelope keys."""
        fixture = _make_canonical_suricata_fixture()
        result = validate_ingestion_envelope(fixture)
        self.assertTrue(result.valid)
        dumped = result.envelope.model_dump()
        self.assertEqual(
            set(dumped.keys()),
            {"ingestion_id", "source_type", "sensor_id", "ingest_time", "raw_hash", "raw_payload"},
        )
        self.assertEqual(dumped["source_type"], "suricata")


class TestInvalidEnvelopesAndMissingFields(unittest.TestCase):
    """Verify rejection behavior for invalid envelopes, missing fields, and bad identifiers."""

    def test_non_dict_payload_rejected(self):
        for bad_payload in (None, [], "raw-string", 12345):
            result = validate_ingestion_envelope(bad_payload)
            self.assertFalse(result.valid)
            self.assertEqual(result.disposition, IngestionDisposition.REJECTED)
            self.assertEqual(result.errors[0].category, ValidationErrorCategory.INVALID_SCHEMA_TYPE)

    def test_missing_required_fields_rejected(self):
        base = _make_canonical_sysmon_fixture()
        required = ("ingestion_id", "source_type", "sensor_id", "ingest_time", "raw_hash", "raw_payload")
        for field_name in required:
            incomplete = dict(base)
            del incomplete[field_name]
            result = validate_ingestion_envelope(incomplete)
            self.assertFalse(result.valid, f"Expected failure when missing {field_name}")
            self.assertEqual(result.disposition, IngestionDisposition.REJECTED)
            self.assertEqual(result.errors[0].category, ValidationErrorCategory.MISSING_REQUIRED_FIELD)
            self.assertEqual(result.errors[0].field, field_name)

    def test_invalid_ingestion_id_rejected(self):
        for bad_id in (
            "not-a-uuid",
            "a1b2c3d4-e5f6-1a8b-9c0d-1e2f3a4b5c6d",
            "00000000-0000-0000-0000-000000000000",
        ):
            fixture = _make_canonical_sysmon_fixture()
            fixture["ingestion_id"] = bad_id
            result = validate_ingestion_envelope(fixture)
            self.assertFalse(result.valid)
            self.assertEqual(result.disposition, IngestionDisposition.REJECTED)
            self.assertTrue(
                any(e.category == ValidationErrorCategory.INVALID_IDENTIFIER and e.field == "ingestion_id" for e in result.errors)
            )

    def test_empty_sensor_id_rejected(self):
        fixture = _make_canonical_sysmon_fixture()
        fixture["sensor_id"] = "   "
        result = validate_ingestion_envelope(fixture)
        self.assertFalse(result.valid)
        self.assertEqual(result.disposition, IngestionDisposition.REJECTED)
        self.assertTrue(
            any(e.category == ValidationErrorCategory.INVALID_IDENTIFIER and e.field == "sensor_id" for e in result.errors)
        )

    def test_invalid_raw_hash_format_and_mismatch_rejected(self):
        fixture = _make_canonical_suricata_fixture()
        fixture["raw_hash"] = "md5:1234"
        result = validate_ingestion_envelope(fixture)
        self.assertFalse(result.valid)
        self.assertTrue(
            any(e.category == ValidationErrorCategory.INVALID_IDENTIFIER and e.field == "raw_hash" for e in result.errors)
        )

        fixture2 = _make_canonical_suricata_fixture()
        fixture2["raw_hash"] = "sha256:" + ("0" * 64)
        result2 = validate_ingestion_envelope(fixture2)
        self.assertFalse(result2.valid)
        self.assertTrue(any(e.category == ValidationErrorCategory.HASH_MISMATCH for e in result2.errors))


class TestTimestampsAndMetadataValidation(unittest.TestCase):
    """Verify timestamp constraints and metadata schema validation rules."""

    def test_invalid_or_non_utc_ingest_time_rejected(self):
        for bad_ts in ("not-a-date", "2026-09-21T06:42:18", "2026-09-21T06:42:18+05:30"):
            fixture = _make_canonical_zeek_fixture()
            fixture["ingest_time"] = bad_ts
            result = validate_ingestion_envelope(fixture)
            self.assertFalse(result.valid)
            self.assertEqual(result.disposition, IngestionDisposition.REJECTED)
            self.assertTrue(any(e.category == ValidationErrorCategory.INVALID_TIMESTAMP for e in result.errors))

    def test_future_ingest_time_flagged_with_warning(self):
        now = datetime(2026, 9, 21, 7, 0, 0, tzinfo=timezone.utc)
        future_ts = (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        fixture = _make_canonical_zeek_fixture()
        fixture["ingest_time"] = future_ts
        result = validate_ingestion_envelope(fixture, now_utc=now)
        self.assertTrue(result.valid)
        self.assertEqual(result.disposition, IngestionDisposition.ACCEPTED_WITH_WARNINGS)
        self.assertTrue(any(w.category == ValidationErrorCategory.INVALID_TIMESTAMP for w in result.warnings))

    def test_invalid_auxiliary_metadata_rejected(self):
        fixture = _make_canonical_sysmon_fixture()
        fixture["metadata"] = {
            "ingest_time": "invalid-ts",
            "pipeline_version": "",
            "raw_hash": "bad-hash",
            "raw_truncated": "yes",
            "tags": [123],
        }
        result = validate_ingestion_envelope(fixture)
        self.assertFalse(result.valid)
        self.assertEqual(result.disposition, IngestionDisposition.REJECTED)
        self.assertGreaterEqual(len(result.errors), 4)

    def test_validate_event_metadata_helper_accepts_valid_metadata(self):
        issues = validate_event_metadata(
            {
                "ingest_time": "2026-09-21T06:42:18.001Z",
                "pipeline_version": "0.2.0",
                "raw_hash": "sha256:" + ("a" * 64),
                "raw_truncated": False,
                "possible_duplicate": False,
                "tags": ["day6-fixture"],
                "source_fields": {"EventID": 1},
            }
        )
        self.assertEqual(issues, [])


class TestUnsupportedFormatsMalformedPayloadsAndNoLeakage(unittest.TestCase):
    """Verify unsupported source handling, malformed payload rejection, and non-leakage."""

    def test_unknown_and_custom_source_types_unsupported(self):
        for unsupported in ("unknown_vendor", "custom"):
            fixture = _make_canonical_sysmon_fixture()
            fixture["source_type"] = unsupported
            result = validate_ingestion_envelope(fixture)
            self.assertFalse(result.valid)
            self.assertEqual(result.disposition, IngestionDisposition.UNSUPPORTED)
            self.assertEqual(result.errors[0].category, ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE)

    def test_malformed_suricata_and_sysmon_payloads_rejected(self):
        bad_suricata = _make_canonical_suricata_fixture()
        bad_suricata["raw_payload"] = "{not-valid-json"
        bad_suricata["raw_hash"] = compute_raw_hash(bad_suricata["raw_payload"])
        res1 = validate_ingestion_envelope(bad_suricata)
        self.assertFalse(res1.valid)
        self.assertEqual(res1.errors[0].category, ValidationErrorCategory.MALFORMED_PAYLOAD)

        bad_sysmon = _make_canonical_sysmon_fixture()
        bad_sysmon["raw_payload"] = "not xml content"
        bad_sysmon["raw_hash"] = compute_raw_hash(bad_sysmon["raw_payload"])
        res2 = validate_ingestion_envelope(bad_sysmon)
        self.assertFalse(res2.valid)
        self.assertEqual(res2.errors[0].category, ValidationErrorCategory.MALFORMED_PAYLOAD)

    def test_oversized_payload_flagged_truncated_with_warning(self):
        oversized_json = json.dumps({"event_type": "alert", "pad": "A" * (MAX_RAW_PAYLOAD_BYTES + 100)})
        fixture = _make_canonical_suricata_fixture()
        fixture["raw_payload"] = oversized_json
        fixture["raw_hash"] = compute_raw_hash(oversized_json)
        result = validate_ingestion_envelope(fixture)
        self.assertTrue(result.valid)
        self.assertTrue(result.raw_truncated)
        self.assertEqual(result.disposition, IngestionDisposition.ACCEPTED_WITH_WARNINGS)
        self.assertTrue(any(w.category == ValidationErrorCategory.PAYLOAD_TRUNCATED for w in result.warnings))

    def test_sensitive_payload_content_not_leaked_in_errors(self):
        secret = "SUPER_SECRET_TOKEN_998877_DO_NOT_LEAK"
        fixture = _make_canonical_suricata_fixture()
        fixture["raw_payload"] = f"{{malformed {secret}"
        fixture["raw_hash"] = "sha256:" + ("f" * 64)
        result = validate_ingestion_envelope(fixture)
        self.assertFalse(result.valid)
        serialized = json.dumps(result.model_dump())
        self.assertNotIn(secret, serialized)


class TestDuplicateIdentityBehavior(unittest.TestCase):
    """Verify duplicate raw_hash and ingestion_id flagging without silent drops."""

    def test_duplicate_tracker_protocol_conformance(self):
        tracker = InMemoryDuplicateTracker()
        self.assertIsInstance(tracker, DuplicateTrackerProtocol)

    def test_duplicate_raw_hash_and_ingestion_id_flagged(self):
        async def _run():
            validator = IngestionEnvelopeValidator()
            first = _make_canonical_zeek_fixture()
            res1 = await validator.validate_envelope(first)
            self.assertTrue(res1.valid)
            self.assertFalse(res1.is_duplicate)
            self.assertEqual(res1.disposition, IngestionDisposition.ACCEPTED)

            # Same raw_hash, new ingestion_id -> flagged as raw_hash duplicate, still accepted
            replay_new_delivery = dict(first)
            replay_new_delivery["ingestion_id"] = "d4e5f6a7-b8c9-4d0e-8f1a-4b5c6d7e8f9a"
            res2 = await validator.validate_envelope(replay_new_delivery)
            self.assertTrue(res2.valid)
            self.assertTrue(res2.is_duplicate)
            self.assertEqual(res2.duplicate_type, "raw_hash")
            self.assertEqual(res2.disposition, IngestionDisposition.ACCEPTED_WITH_WARNINGS)

            # Exact same ingestion_id -> flagged as ingestion_id duplicate, still accepted
            res3 = await validator.validate_envelope(first)
            self.assertTrue(res3.valid)
            self.assertTrue(res3.is_duplicate)
            self.assertEqual(res3.duplicate_type, "ingestion_id")
            self.assertEqual(res3.disposition, IngestionDisposition.ACCEPTED_WITH_WARNINGS)

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main()
