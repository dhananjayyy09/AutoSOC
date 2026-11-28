"""
AutoSOC Day 10 - Threat Intelligence Provider Contract & Adapter Tests

Verifies:
- ThreatIntelProviderProtocol conformance and provider-neutral lookup contract
- Valid observable lookups (IP, domain, URL, file hash) with controlled synthetic fixtures
- Unsupported observable types & pre-lookup rejection of malformed indicators
- Provider no_result vs unavailable, timeout, exception, and malformed_response handling
- Conservative verdict rules (unknown on no_result or benign/malicious conflict)
- Response sanitization (forbidden secret/raw_event keys stripped, confidence never fabricated)
- Observable deduplication, provenance preservation, and partial enrichment results
- Zero external network calls during default tests
"""

import copy
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch
import urllib.request

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.events.schemas import (
    EventCategoryEnum,
    NormalizedSecurityEvent,
    SourceTypeEnum,
)
from app.threat_intelligence import (
    EnrichmentStatusEnum,
    FixtureThreatIntelProvider,
    ObservableLookupRequest,
    ObservableLookupResult,
    ObservableTypeEnum,
    ObservableVerdictEnum,
    ProviderLookupStatusEnum,
    ThreatIntelObservablePipeline,
    ThreatIntelProviderProtocol,
    sanitize_provider_response,
    validate_observable_for_lookup,
)


def _make_event(**overrides) -> NormalizedSecurityEvent:
    base = {
        "event_id": "22222222-3333-4444-8555-666666666666",
        "ingestion_id": "b1b2c3d4-e5f6-4a8b-9c0d-1e2f3a4b5c6d",
        "timestamp": "2026-09-21T08:00:00.000Z",
        "source": SourceTypeEnum.SURICATA,
        "event_category": EventCategoryEnum.ALERT,
        "event_type": "alert.ids",
        "host": "sensor-edge-test",
        "severity": 5,
        "raw_event": '{"event_type":"alert","secret_raw":"MUST_NOT_REACH_PROVIDER"}',
        "metadata": {
            "ingest_time": "2026-09-21T08:00:00.500Z",
            "pipeline_version": "0.2.0",
            "raw_hash": "sha256:" + ("0" * 64),
            "source_fields": {},
        },
    }
    base.update(overrides)
    return NormalizedSecurityEvent(**base)


class TestProviderContractAndFixtures(unittest.TestCase):
    """Verify protocol conformance and valid controlled fixture lookups."""

    def setUp(self):
        self.provider = FixtureThreatIntelProvider()

    def test_fixture_provider_conforms_to_protocol(self):
        self.assertIsInstance(self.provider, ThreatIntelProviderProtocol)
        self.assertFalse(self.provider.is_live_lookup)
        self.assertEqual(self.provider.provider_name, "autosoc.mock_ti_fixture")

    def test_valid_observable_lookups_across_types(self):
        cases = [
            (ObservableTypeEnum.IP, "203.0.113.99", ObservableVerdictEnum.MALICIOUS, 0.92),
            (ObservableTypeEnum.IP, "198.51.100.10", ObservableVerdictEnum.BENIGN, 0.85),
            (ObservableTypeEnum.DOMAIN, "malicious-sim.example.invalid", ObservableVerdictEnum.MALICIOUS, 0.88),
            (ObservableTypeEnum.URL, "https://phish-sim.example.invalid/login", ObservableVerdictEnum.SUSPICIOUS, 0.70),
            (ObservableTypeEnum.FILE_HASH, "sha256:" + ("e" * 64), ObservableVerdictEnum.MALICIOUS, 0.99),
        ]
        fixed_ts = "2026-09-21T08:05:00.000Z"
        for obs_type, norm_val, exp_verdict, exp_conf in cases:
            req = ObservableLookupRequest(observable_type=obs_type, normalized_value=norm_val)
            res = self.provider.lookup(req, lookup_timestamp=fixed_ts)
            self.assertIsInstance(res, ObservableLookupResult)
            self.assertEqual(res.lookup_status, ProviderLookupStatusEnum.FOUND)
            self.assertEqual(res.verdict, exp_verdict)
            self.assertEqual(res.confidence, exp_conf)
            self.assertEqual(res.lookup_timestamp, fixed_ts)
            self.assertFalse(res.live_lookup_performed)
            self.assertTrue(len(res.references) >= 1)
            self.assertTrue(len(res.evidence) >= 1)


class TestObservableValidationAndUnsupportedTypes(unittest.TestCase):
    """Verify malformed inputs and unsupported observable types are rejected safely."""

    def test_malformed_observables_rejected_pre_lookup_without_transformation(self):
        bad_inputs = [
            (ObservableTypeEnum.IP, "192.168.1.999"),
            (ObservableTypeEnum.IP, "not-an-ip"),
            (ObservableTypeEnum.DOMAIN, "8.8.8.8"),
            (ObservableTypeEnum.DOMAIN, "bad domain!"),
            (ObservableTypeEnum.URL, "javascript:alert(1)"),
            (ObservableTypeEnum.URL, "https://example.invalid/has space"),
            (ObservableTypeEnum.FILE_HASH, "sha256:not_hex"),
            (ObservableTypeEnum.FILE_HASH, "deadbeef"),
        ]
        pipeline = ThreatIntelObservablePipeline()
        for obs_type, bad_val in bad_inputs:
            is_valid, _, canonical, err = validate_observable_for_lookup(obs_type, bad_val)
            self.assertFalse(is_valid, f"Expected pre-lookup rejection for {obs_type}: {bad_val}")
            self.assertIsNone(canonical)
            self.assertIsNotNone(err)

            results = pipeline.lookup_observable(obs_type, bad_val)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].lookup_status, ProviderLookupStatusEnum.INVALID_OBSERVABLE)
            self.assertEqual(results[0].verdict, ObservableVerdictEnum.UNKNOWN)
            self.assertIsNone(results[0].confidence)

    def test_unsupported_observable_type_handled_cleanly(self):
        ip_only_provider = FixtureThreatIntelProvider(
            provider_name="ip_only_mock",
            supported_types=frozenset({ObservableTypeEnum.IP}),
        )
        req = ObservableLookupRequest(
            observable_type=ObservableTypeEnum.DOMAIN,
            normalized_value="malicious-sim.example.invalid",
        )
        res = ip_only_provider.lookup(req)
        self.assertEqual(res.lookup_status, ProviderLookupStatusEnum.UNSUPPORTED_OBSERVABLE)
        self.assertEqual(res.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertIsNone(res.confidence)

        # Invalid observable type enum rejected safely
        pipeline = ThreatIntelObservablePipeline(ti_providers=[ip_only_provider])
        res_bad_type = pipeline.lookup_observable("mac_address", "aa:bb:cc:dd:ee:ff")
        self.assertEqual(res_bad_type[0].lookup_status, ProviderLookupStatusEnum.UNSUPPORTED_OBSERVABLE)


class TestProviderFailuresNoResultAndSanitization(unittest.TestCase):
    """Verify no_result, timeout, unavailable, malformed response, and secret stripping."""

    def setUp(self):
        self.provider = FixtureThreatIntelProvider()

    def test_provider_no_result_preserves_unknown_and_no_fabricated_confidence(self):
        req = ObservableLookupRequest(
            observable_type=ObservableTypeEnum.IP,
            normalized_value="8.8.8.8",
        )
        res = self.provider.lookup(req)
        self.assertEqual(res.lookup_status, ProviderLookupStatusEnum.NO_RESULT)
        self.assertEqual(res.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertIsNone(res.confidence)
        self.assertEqual(res.evidence, {})
        self.assertEqual(res.references, [])
        self.assertEqual(res.errors, [])
        self.assertEqual(res.warnings, [])

    def test_provider_timeout_and_unavailable_simulated(self):
        res_timeout = self.provider.lookup(
            ObservableLookupRequest(observable_type=ObservableTypeEnum.IP, normalized_value="203.0.113.250")
        )
        self.assertEqual(res_timeout.lookup_status, ProviderLookupStatusEnum.TIMEOUT)
        self.assertEqual(res_timeout.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertIsNone(res_timeout.confidence)
        self.assertEqual(len(res_timeout.errors), 1)

        res_unavail = self.provider.lookup(
            ObservableLookupRequest(observable_type=ObservableTypeEnum.IP, normalized_value="203.0.113.251")
        )
        self.assertEqual(res_unavail.lookup_status, ProviderLookupStatusEnum.UNAVAILABLE)
        self.assertEqual(res_unavail.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertIsNone(res_unavail.confidence)

    def test_malformed_provider_response_rejected(self):
        res = self.provider.lookup(
            ObservableLookupRequest(
                observable_type=ObservableTypeEnum.DOMAIN,
                normalized_value="malformed-resp.example.invalid",
            )
        )
        self.assertEqual(res.lookup_status, ProviderLookupStatusEnum.MALFORMED_RESPONSE)
        self.assertEqual(res.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertIsNone(res.confidence)

        for bad_raw in (
            "not-an-object",
            {"evidence": {}},  # missing verdict
            {"verdict": "malicious", "confidence": float("nan")},
            {"verdict": "malicious", "confidence": 1.5},
            {"verdict": "malicious", "evidence": ["not-a-dict"]},
            {"verdict": "malicious", "references": [{"source_name": "x", "reference_url": "javascript:alert(1)"}]},
        ):
            sanitized = sanitize_provider_response(
                bad_raw,
                provider_name="test_p",
                provider_version="0.1",
                observable_type=ObservableTypeEnum.IP,
                normalized_value="203.0.113.99",
                live_lookup_performed=False,
            )
            self.assertEqual(sanitized.lookup_status, ProviderLookupStatusEnum.MALFORMED_RESPONSE)
            self.assertEqual(sanitized.verdict, ObservableVerdictEnum.UNKNOWN)
            self.assertIsNone(sanitized.confidence)

    def test_secret_keys_and_control_chars_stripped_from_provider_evidence(self):
        sanitized = sanitize_provider_response(
            {
                "verdict": "benign",
                "evidence": {
                    "api_key": "SECRET_KEY_123",
                    "authorization": "Bearer abc",
                    "raw_event": "should_be_stripped",
                    "nested": {"token": "HIDE_ME", "safe_note": "ok\nline"},
                },
            },
            provider_name="test_p",
            provider_version="0.1",
            observable_type=ObservableTypeEnum.IP,
            normalized_value="198.51.100.10",
            live_lookup_performed=False,
        )
        self.assertEqual(sanitized.lookup_status, ProviderLookupStatusEnum.FOUND)
        self.assertIsNone(sanitized.confidence)  # omitted confidence is never fabricated
        dumped = json.dumps(sanitized.model_dump())
        for secret in ("SECRET_KEY_123", "Bearer abc", "should_be_stripped", "HIDE_ME"):
            self.assertNotIn(secret, dumped)
        self.assertEqual(sanitized.evidence["nested"]["safe_note"], "ok line")


class TestPipelineNormalizationPartialAndNetworkIsolation(unittest.TestCase):
    """Verify Day 9 normalization, deduplication, partial results, conflicts, and no network calls."""

    def test_minimal_requests_deduplication_provenance_and_unknown_high_severity(self):
        observed_requests = []

        class SpyProvider(FixtureThreatIntelProvider):
            def lookup(self, request, *, lookup_timestamp=None):
                observed_requests.append(request.model_dump())
                return super().lookup(request, lookup_timestamp=lookup_timestamp)

        pipeline = ThreatIntelObservablePipeline(ti_providers=[SpyProvider()])
        # Repeated IP 8.8.8.8 (no_result -> remains unknown despite severity=5 and external IP)
        ev = _make_event(
            severity=5,
            source_ip="8.8.8.8",
            destination_ip="8.8.8.8",
            destination_port=4444,
        )
        original_snapshot = copy.deepcopy(ev.model_dump())

        res = pipeline.enrich_with_threat_intel(ev, enriched_at="2026-09-21T08:10:00.000Z")
        self.assertEqual(res.enrichment_status, EnrichmentStatusEnum.ENRICHED)
        self.assertEqual(res.observable_count, 1)
        # Deduplicated: provider queried exactly once, and request contains only observable fields
        self.assertEqual(len(observed_requests), 1)
        self.assertEqual(set(observed_requests[0].keys()), {"observable_type", "normalized_value"})
        self.assertNotIn("MUST_NOT_REACH_PROVIDER", json.dumps(observed_requests))

        obs = res.observables[0]
        self.assertEqual(obs.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertEqual(obs.provenance.source_fields, ["source_ip", "destination_ip"])
        self.assertEqual(obs.provenance.source_event_id, ev.event_id)
        self.assertEqual(obs.provenance.ingestion_id, ev.ingestion_id)
        self.assertFalse(obs.provenance.live_lookup_performed)
        # Original event completely untouched
        self.assertEqual(ev.model_dump(), original_snapshot)

    def test_partial_enrichment_when_one_observable_times_out_and_another_succeeds(self):
        pipeline = ThreatIntelObservablePipeline()
        ev = _make_event(
            source_ip="203.0.113.99",       # FOUND -> malicious
            destination_ip="203.0.113.250", # TIMEOUT
        )
        res = pipeline.enrich_with_threat_intel(ev)
        self.assertEqual(res.enrichment_status, EnrichmentStatusEnum.ENRICHED_PARTIAL)
        self.assertEqual(res.observable_count, 2)
        by_val = {o.normalized_value: o for o in res.observables}
        self.assertEqual(by_val["203.0.113.99"].verdict, ObservableVerdictEnum.MALICIOUS)
        self.assertEqual(by_val["203.0.113.250"].verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertTrue(any("timeout" in w.message for w in res.warnings))
        self.assertFalse(res.live_lookup_performed)

    def test_conflicting_providers_resolve_conservatively_to_unknown(self):
        p_mal = FixtureThreatIntelProvider(
            provider_name="mock_a",
            fixtures={
                ("ip", "203.0.113.99"): {
                    "verdict": "malicious",
                    "confidence": 0.9,
                    "evidence": {"fixture_id": "CONFLICT-MAL"},
                }
            },
        )
        p_benign = FixtureThreatIntelProvider(
            provider_name="mock_b",
            fixtures={
                ("ip", "203.0.113.99"): {
                    "verdict": "benign",
                    "confidence": 0.95,
                    "evidence": {"fixture_id": "CONFLICT-BENIGN"},
                }
            },
        )
        pipeline = ThreatIntelObservablePipeline(ti_providers=[p_mal, p_benign])
        ev = _make_event(source_ip="203.0.113.99")
        res = pipeline.enrich_with_threat_intel(ev)
        self.assertEqual(res.enrichment_status, EnrichmentStatusEnum.ENRICHED_PARTIAL)
        self.assertEqual(res.observables[0].verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertIsNone(res.observables[0].context["threat_intel"]["confidence"])
        self.assertTrue(any("Conflicting provider verdicts" in w.message for w in res.warnings))

    def test_zero_external_network_calls_in_default_pipeline(self):
        pipeline = ThreatIntelObservablePipeline()
        ev = _make_event(
            source_ip="203.0.113.99",
            domain="malicious-sim.example.invalid",
        )
        with patch.object(
            socket, "create_connection", side_effect=AssertionError("Network call attempted")
        ), patch.object(
            urllib.request, "urlopen", side_effect=AssertionError("HTTP call attempted")
        ):
            res = pipeline.enrich_with_threat_intel(ev)
        self.assertEqual(res.enrichment_status, EnrichmentStatusEnum.ENRICHED)
        self.assertFalse(res.live_lookup_performed)


if __name__ == "__main__":
    unittest.main()
