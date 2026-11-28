"""
AutoSOC Day 13 - Security Foundation Contract Stability & Mapping Tests

Covers:
  1. TI Provider Contracts & SyncTIProviderAdapter status/security-invariant enforcement
  2. Observable `context["threat_intel"]` multi-level structure & top-level alignment
  3. Normalized event field mapping consistency across domain schema, SQL DDL, API, and query contract
  4. Enrichment result contract serialization and provenance preservation
  5. Ingestion validation boundary checks (valid, invalid, missing, boundary cases)
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
from app.events.query_contract import (  # noqa: E402
    EXPLICITLY_FORBIDDEN_SEARCH_FIELDS,
    SEARCHABLE_NORMALIZED_EVENT_FIELDS,
    SORT_FIELD_TO_ORM_COLUMN,
    NormalizedEventSortField,
    validate_normalized_event_query,
)
from app.events.schemas import (  # noqa: E402
    PYDANTIC_V2,
    IngestionEnvelope,
    NormalizationStatusEnum,
    NormalizedSecurityEvent,
    SourceTypeEnum,
)
from app.events.validation import (  # noqa: E402
    MAX_RAW_PAYLOAD_BYTES,
    IngestionDisposition,
    ValidationErrorCategory,
    compute_raw_hash,
    validate_ingestion_envelope,
)
from app.threat_intelligence import (  # noqa: E402
    DeterministicEventEnricher,
    EnrichmentStatusEnum,
    EventEnrichmentResult,
    FixtureThreatIntelProvider,
    ObservableLookupResult,
    ObservableTypeEnum,
    ObservableVerdictEnum,
    ProviderLookupStatusEnum,
    ProviderReference,
    SyncTIProviderAdapter,
    ThreatIntelLookupRequest,
    ThreatIntelLookupStatusEnum,
    ThreatIntelObservablePipeline,
    ThreatIntelProviderProtocol,
)


def _envelope_payload(
    *,
    source_type: str = "suricata",
    raw_payload: str = '{"timestamp":"2026-11-28T18:00:00Z","event_type":"alert","host":"fw-day13-01","src_ip":"10.0.0.10","src_port":51234,"dest_ip":"203.0.113.99","dest_port":443,"proto":"TCP","alert":{"signature":"ET Synthetic Alert","severity":2}}',
    ingestion_id: str = "11111111-1111-4111-8111-111111111111",
    sensor_id: str = "sensor-day13-01",
    ingest_time: str = "2026-11-28T18:00:01Z",
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


class TestDay13TIProviderAndAdapterContracts(unittest.TestCase):
    """Verify SyncTIProviderAdapter compatibility, status mapping, and verdict invariants."""

    def test_sync_adapter_status_mapping_and_minimal_request_forwarding(self):
        observed_requests = []

        class SpyFixtureProvider(FixtureThreatIntelProvider):
            def lookup(self, request, *, lookup_timestamp=None):
                observed_requests.append(request.model_dump())
                return super().lookup(request, lookup_timestamp=lookup_timestamp)

        provider = SpyFixtureProvider()
        self.assertIsInstance(provider, ThreatIntelProviderProtocol)
        adapter = SyncTIProviderAdapter(provider)
        self.assertEqual(adapter.provider_id, provider.provider_name)
        self.assertEqual(adapter.provider_version, provider.provider_version)
        self.assertFalse(adapter.is_live_lookup)
        self.assertTrue(adapter.supports_observable(ObservableTypeEnum.IP))

        cases = [
            ("203.0.113.99", ThreatIntelLookupStatusEnum.SUCCESS.value, "malicious"),
            ("198.51.100.10", ThreatIntelLookupStatusEnum.SUCCESS.value, "benign"),
            ("8.8.8.8", ThreatIntelLookupStatusEnum.NO_DATA.value, "unknown"),
            ("203.0.113.250", ThreatIntelLookupStatusEnum.TIMEOUT.value, "unknown"),
            ("203.0.113.251", ThreatIntelLookupStatusEnum.UNAVAILABLE.value, "unknown"),
            ("203.0.113.252", ThreatIntelLookupStatusEnum.RATE_LIMITED.value, "unknown"),
        ]

        async def _run():
            for ip_val, exp_status, exp_verdict in cases:
                out = await adapter.lookup(
                    ThreatIntelLookupRequest(
                        observable_type=ObservableTypeEnum.IP,
                        normalized_value=ip_val,
                        source_event_id="evt-day13-leak-check",
                        ingestion_id="ing-day13-leak-check",
                    )
                )
                self.assertEqual(out["lookup_status"], exp_status)
                self.assertEqual(out["verdict"], exp_verdict)
                self.assertFalse(out["live_lookup_performed"])

        asyncio.run(_run())
        self.assertEqual(len(observed_requests), len(cases))
        for req_dump in observed_requests:
            self.assertEqual(set(req_dump.keys()), {"observable_type", "normalized_value"})

    def test_sync_adapter_downgrades_unsubstantiated_or_failed_verdicts(self):
        class BrokenSyncProvider(FixtureThreatIntelProvider):
            def lookup(self, request, *, lookup_timestamp=None):
                if request.normalized_value == "203.0.113.77":
                    # Found + malicious WITHOUT evidence or references -> invalid
                    return ObservableLookupResult(
                        provider_name=self.provider_name,
                        provider_version=self.provider_version,
                        observable_type=request.observable_type,
                        normalized_value=request.normalized_value,
                        lookup_status=ProviderLookupStatusEnum.FOUND,
                        verdict=ObservableVerdictEnum.MALICIOUS,
                        confidence=0.95,
                        evidence={},
                        references=[],
                        lookup_timestamp="2026-11-29T00:00:00Z",
                        live_lookup_performed=False,
                    )
                if request.normalized_value == "203.0.113.78":
                    # Failed status claiming malicious -> downgraded to unknown
                    return ObservableLookupResult(
                        provider_name=self.provider_name,
                        provider_version=self.provider_version,
                        observable_type=request.observable_type,
                        normalized_value=request.normalized_value,
                        lookup_status=ProviderLookupStatusEnum.TIMEOUT,
                        verdict=ObservableVerdictEnum.MALICIOUS,
                        confidence=0.88,
                        evidence={"note": "should be stripped"},
                        references=[],
                        lookup_timestamp="2026-11-29T00:00:00Z",
                        live_lookup_performed=False,
                    )
                # Found + malicious backed by reference metadata (no dict evidence) -> allowed
                return ObservableLookupResult(
                    provider_name=self.provider_name,
                    provider_version=self.provider_version,
                    observable_type=request.observable_type,
                    normalized_value=request.normalized_value,
                    lookup_status=ProviderLookupStatusEnum.FOUND,
                    verdict=ObservableVerdictEnum.MALICIOUS,
                    confidence=0.80,
                    evidence={},
                    references=[ProviderReference(source_name="synth_feed", reference_id="REF-79")],
                    lookup_timestamp="2026-11-29T00:00:00Z",
                    live_lookup_performed=False,
                )

        adapter = SyncTIProviderAdapter(BrokenSyncProvider())

        async def _run():
            r_no_ev = await adapter.lookup(
                ThreatIntelLookupRequest(
                    observable_type=ObservableTypeEnum.IP,
                    normalized_value="203.0.113.77",
                    source_event_id=None,
                    ingestion_id="11111111-1111-4111-8111-111111111111",
                )
            )
            r_timeout_mal = await adapter.lookup(
                ThreatIntelLookupRequest(
                    observable_type=ObservableTypeEnum.IP,
                    normalized_value="203.0.113.78",
                    source_event_id=None,
                    ingestion_id="11111111-1111-4111-8111-111111111111",
                )
            )
            r_ref_backed = await adapter.lookup(
                ThreatIntelLookupRequest(
                    observable_type=ObservableTypeEnum.IP,
                    normalized_value="203.0.113.79",
                    source_event_id=None,
                    ingestion_id="11111111-1111-4111-8111-111111111111",
                )
            )
            return r_no_ev, r_timeout_mal, r_ref_backed

        r_no_ev, r_timeout_mal, r_ref_backed = asyncio.run(_run())
        self.assertEqual(r_no_ev["lookup_status"], ThreatIntelLookupStatusEnum.INVALID_RESPONSE.value)
        self.assertEqual(r_no_ev["verdict"], "unknown")
        self.assertIsNone(r_no_ev["confidence"])

        self.assertEqual(r_timeout_mal["lookup_status"], ThreatIntelLookupStatusEnum.TIMEOUT.value)
        self.assertEqual(r_timeout_mal["verdict"], "unknown")
        self.assertIsNone(r_timeout_mal["confidence"])

        self.assertEqual(r_ref_backed["lookup_status"], ThreatIntelLookupStatusEnum.SUCCESS.value)
        self.assertEqual(r_ref_backed["verdict"], "malicious")
        self.assertEqual(r_ref_backed["confidence"], 0.80)
        self.assertIn("synth_feed", r_ref_backed["evidence"])
        self.assertEqual(len(r_ref_backed["references"]), 1)


class TestDay13ObservableContextAndMappings(unittest.TestCase):
    """Verify observable TI context structure, normalized event mapping, and enrichment roundtrip."""

    def test_observable_threat_intel_context_dict_shape_and_top_level_fields(self):
        normalizer = DeterministicEventNormalizer()
        env = _envelope_payload(source_type="suricata")
        norm = normalizer.normalize_envelope(env)
        self.assertEqual(norm.normalization_status, NormalizationStatusEnum.NORMALIZED)
        assert norm.event is not None

        pipeline = ThreatIntelObservablePipeline(
            base_enricher=DeterministicEventEnricher(),
            ti_providers=[FixtureThreatIntelProvider()],
        )
        res = pipeline.enrich_with_threat_intel(
            norm.event, enriched_at="2026-11-29T00:05:00.000Z"
        )
        self.assertIsInstance(res, EventEnrichmentResult)

        dumped = res.model_dump()
        rehydrated = json.loads(json.dumps(dumped))
        self.assertEqual(rehydrated["enrichment_status"], "enriched")

        by_val = {o["normalized_value"]: o for o in rehydrated["observables"]}
        mal_obs = by_val["203.0.113.99"]
        # Observable-level TI summary fields aligned with CanonicalEnrichedObservable
        self.assertEqual(mal_obs["verdict"], "malicious")
        self.assertEqual(mal_obs["confidence"], 0.92)
        self.assertEqual(mal_obs["lookup_status"], "found")
        self.assertEqual(mal_obs["lookup_timestamp"], "2026-11-29T00:05:00.000Z")
        self.assertFalse(mal_obs["live_lookup_performed"])
        self.assertIsInstance(mal_obs["references"], list)
        self.assertEqual(mal_obs["references"][0]["reference_id"], "FIXTURE-IP-001")
        # PipeLine per-observable context["threat_intel"] preserves dict shape {verdict, confidence, lookups}
        ti_ctx = mal_obs["context"]["threat_intel"]
        self.assertIsInstance(ti_ctx, dict)
        self.assertEqual(ti_ctx["verdict"], "malicious")
        self.assertEqual(len(ti_ctx["lookups"]), 1)

    def test_normalized_event_schema_orm_sql_and_query_mapping_consistency(self):
        sql_path = (
            Path(__file__).resolve().parent.parent
            / "app"
            / "db"
            / "migrations"
            / "002_create_normalized_events.sql"
        )
        ddl_text = sql_path.read_text(encoding="utf-8")

        # Domain field names -> SQL persistence column names
        expected_db_columns = {
            "event_id",
            "raw_envelope_id",
            "ingestion_id",
            "event_timestamp",
            "source_type",
            "sensor_id",
            "event_category",
            "event_type",
            "host",
            "user_name",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
            "process",
            "file_hash",
            "domain",
            "command_line",
            "severity",
            "metadata",
            "normalization_status",
            "normalization_errors",
            "normalization_warnings",
            "created_at",
        }
        for col in expected_db_columns:
            self.assertIn(col, ddl_text, f"Missing normalized_events DDL column: {col}")

        # Query contract sortable & searchable fields only target persisted normalized columns
        for sort_enum in NormalizedEventSortField:
            orm_col = SORT_FIELD_TO_ORM_COLUMN[sort_enum]
            self.assertIn(orm_col, expected_db_columns)

        for search_col in SEARCHABLE_NORMALIZED_EVENT_FIELDS:
            self.assertIn(search_col, expected_db_columns)
            self.assertNotIn(search_col, EXPLICITLY_FORBIDDEN_SEARCH_FIELDS)

        # Verify Suricata, Sysmon, and Zeek domain models contain canonical mapping keys
        normalizer = DeterministicEventNormalizer()
        samples = [
            _envelope_payload(
                source_type="suricata",
                raw_payload='{"timestamp":"2026-11-29T00:00:00Z","event_type":"alert","host":"fw-1","src_ip":"10.0.0.1","dest_ip":"203.0.113.99","proto":"TCP","alert":{"severity":1}}',
            ),
            _envelope_payload(
                source_type="sysmon",
                raw_payload="<Event><System><EventID>1</EventID><TimeCreated SystemTime='2026-11-29T00:00:00Z'/><Computer>win-01</Computer></System><EventData><Data Name='User'>CORP\\alice</Data><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data></EventData></Event>",
            ),
            _envelope_payload(
                source_type="zeek",
                raw_payload='{"ts":1732838400.0,"uid":"CZ1","id.orig_h":"10.0.0.2","id.resp_h":"8.8.8.8","proto":"udp","query":"example.invalid"}',
            ),
        ]
        for env in samples:
            norm = normalizer.normalize_envelope(env)
            self.assertIn(
                norm.normalization_status,
                (
                    NormalizationStatusEnum.NORMALIZED,
                    NormalizationStatusEnum.NORMALIZED_WITH_WARNINGS,
                ),
            )
            self.assertIsNotNone(norm.event)
            dumped = norm.event.model_dump()
            # Domain fields that translate cleanly into ORM / API columns
            self.assertIn("source", dumped)
            self.assertIn("timestamp", dumped)
            self.assertIn("metadata", dumped)
            self.assertIn("sensor_id", dumped["metadata"])

        # Query validation boundary sanity
        q_ok = validate_normalized_event_query({"source_type": "sysmon", "severity": 3, "limit": 50})
        self.assertTrue(q_ok.valid)
        self.assertEqual(q_ok.params.source_type, SourceTypeEnum.SYSMON)


class TestDay13IngestionValidationBoundaries(unittest.TestCase):
    """Verify valid, invalid, missing, and boundary cases for ingestion validation."""

    def test_valid_missing_malformed_and_boundary_envelopes(self):
        # Missing required fields
        base = _envelope_payload()
        for req_field in (
            "ingestion_id",
            "source_type",
            "sensor_id",
            "ingest_time",
            "raw_hash",
            "raw_payload",
        ):
            incomplete = copy.deepcopy(base)
            del incomplete[req_field]
            res = validate_ingestion_envelope(incomplete)
            self.assertFalse(res.valid)
            self.assertEqual(res.disposition, IngestionDisposition.REJECTED)
            self.assertEqual(res.errors[0].category, ValidationErrorCategory.MISSING_REQUIRED_FIELD)

        # Exact 64 KiB boundary succeeds; +1 byte triggers raw_truncated
        prefix = '{"timestamp":"2026-11-29T00:00:00Z","event_type":"alert","note":"'
        suffix = '"}'
        exact_padding = "A" * (MAX_RAW_PAYLOAD_BYTES - len(prefix) - len(suffix))
        exact_payload = prefix + exact_padding + suffix
        self.assertEqual(len(exact_payload.encode("utf-8")), MAX_RAW_PAYLOAD_BYTES)
        res_exact = validate_ingestion_envelope(_envelope_payload(raw_payload=exact_payload))
        self.assertTrue(res_exact.valid)
        self.assertFalse(res_exact.raw_truncated)

        over_payload = exact_payload[:-2] + 'X"}'
        self.assertEqual(len(over_payload.encode("utf-8")), MAX_RAW_PAYLOAD_BYTES + 1)
        res_over = validate_ingestion_envelope(_envelope_payload(raw_payload=over_payload))
        # validate_ingestion_envelope flags raw_truncated=True + warning so HTTP endpoint enforces 422
        self.assertTrue(res_over.valid)
        self.assertEqual(res_over.disposition, IngestionDisposition.ACCEPTED_WITH_WARNINGS)
        self.assertTrue(res_over.raw_truncated)

        # Rejects non-v4 UUID, non-UTC offset, uppercase raw_hash, whitespace payload
        bad_uuid = _envelope_payload(ingestion_id="11111111-1111-1111-8111-111111111111")
        self.assertFalse(validate_ingestion_envelope(bad_uuid).valid)

        non_utc = _envelope_payload(ingest_time="2026-11-29T05:30:00+05:30")
        self.assertFalse(validate_ingestion_envelope(non_utc).valid)

        upper_hash = _envelope_payload()
        upper_hash["raw_hash"] = "sha256:" + upper_hash["raw_hash"].split(":", 1)[1].upper()
        self.assertFalse(validate_ingestion_envelope(upper_hash).valid)

        ws_payload = _envelope_payload(raw_payload="   \t\n  ")
        self.assertFalse(validate_ingestion_envelope(ws_payload).valid)

        # Unsupported custom source_type produces deterministic UNSUPPORTED disposition
        custom_res = validate_ingestion_envelope(
            _envelope_payload(source_type="custom", raw_payload="raw line")
        )
        self.assertFalse(custom_res.valid)
        self.assertEqual(custom_res.disposition, IngestionDisposition.UNSUPPORTED)

    @unittest.skipUnless(PYDANTIC_V2, "Requires Pydantic v2 for EventIngestionRequest DTO validation")
    def test_event_ingestion_request_dto_aligned_with_runtime_validator(self):
        from pydantic import ValidationError
        from app.events.api_schemas import EventIngestionRequest

        valid = EventIngestionRequest(**_envelope_payload())
        self.assertEqual(valid.source_type, SourceTypeEnum.SURICATA)

        for bad_kwargs in (
            {"ingestion_id": "11111111-1111-1111-8111-111111111111"},  # UUID v1
            {"ingest_time": "2026-11-29T05:30:00+05:30"},  # non-UTC
            {"raw_hash": "sha256:" + ("A" * 64)},  # uppercase hex
            {"raw_payload": "   "},  # whitespace only
        ):
            with self.assertRaises(ValidationError):
                EventIngestionRequest(**_envelope_payload(**bad_kwargs))


if __name__ == "__main__":
    unittest.main()
