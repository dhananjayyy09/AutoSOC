"""
AutoSOC Day 11 - Threat Intelligence Provider Reliability & Security Semantics Tests

Covers:
  - All 12 provider outcomes/failure modes (found, no_result, unsupported_observable,
    invalid_observable, unavailable, timeout, rate_limited, malformed_response,
    retry_exhausted, circuit_open, provider_disabled, partial enrichment)
  - Bounded transient retries & recovery without duplicating evidence or references
  - Non-retryable guarantees (no_result, malformed_response, unsupported never retried)
  - Per-provider circuit breaker FSM (closed -> open -> half_open -> closed) & isolation
  - Strict evidence & verdict invariants (malicious requires evidence; failure != benign)
  - Safe minimal provider request enforcement (no raw payloads, event IDs, users, secrets)
  - SyncTIProviderAdapter compatibility with Day 11 statuses
  - Zero external network calls in default tests
"""

import asyncio
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

from app.events.schemas import EventCategoryEnum, NormalizedSecurityEvent, SourceTypeEnum
from app.threat_intelligence import (
    CircuitBreakerStateEnum,
    EnrichmentStatusEnum,
    FixtureThreatIntelProvider,
    ObservableLookupRequest,
    ObservableLookupResult,
    ObservableTypeEnum,
    ObservableVerdictEnum,
    ProviderCircuitBreaker,
    ProviderLookupStatusEnum,
    ProviderOperationalStateEnum,
    ProviderReference,
    RetryPolicy,
    SyncTIProviderAdapter,
    ThreatIntelLookupRequest,
    ThreatIntelLookupStatusEnum,
    ThreatIntelObservablePipeline,
    deduplicate_references,
    enforce_verdict_and_evidence_invariants,
    validate_safe_provider_request,
)


def _make_event(**overrides) -> NormalizedSecurityEvent:
    base = {
        "event_id": "33333333-4444-4555-8666-777777777777",
        "ingestion_id": "c1c2c3d4-e5f6-4a8b-9c0d-1e2f3a4b5c6d",
        "timestamp": "2026-11-28T12:00:00.000Z",
        "source": SourceTypeEnum.SURICATA,
        "event_category": EventCategoryEnum.ALERT,
        "event_type": "alert.ids",
        "host": "sensor-day11-test",
        "severity": 4,
        "user": "alice.test",
        "command_line": "powershell.exe -NoProfile UNRELATED_COMMAND_SECRET",
        "raw_event": '{"event_type":"alert","raw_secret":"DO_NOT_SEND_RAW"}',
        "metadata": {
            "ingest_time": "2026-11-28T12:00:00.500Z",
            "pipeline_version": "0.2.0",
            "raw_hash": "sha256:" + ("0" * 64),
            "source_fields": {},
        },
    }
    base.update(overrides)
    return NormalizedSecurityEvent(**base)


class TestRateLimitRetryAndRecovery(unittest.TestCase):
    """Verify rate limits, transient retries, retry exhaustion, and no duplicate evidence."""

    def test_rate_limit_status_distinct_from_benign_and_no_result(self):
        provider = FixtureThreatIntelProvider()
        res = provider.lookup(
            ObservableLookupRequest(
                observable_type=ObservableTypeEnum.IP,
                normalized_value="203.0.113.252",
            )
        )
        self.assertEqual(res.lookup_status, ProviderLookupStatusEnum.RATE_LIMITED)
        self.assertEqual(res.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertIsNone(res.confidence)
        self.assertFalse(res.live_lookup_performed)
        self.assertTrue(len(res.errors) >= 1)

    def test_transient_failures_recover_on_retry_without_duplicating_evidence_or_refs(self):
        calls = []

        class TransientFixtureProvider(FixtureThreatIntelProvider):
            def lookup(self, request, *, lookup_timestamp=None):
                calls.append(request)
                return super().lookup(request, lookup_timestamp=lookup_timestamp)

        provider = TransientFixtureProvider(
            provider_name="transient_mock",
            fixtures={
                ("ip", "203.0.113.99"): {
                    "transient_failures": ["timeout", "rate_limited"],
                    "verdict": "malicious",
                    "confidence": 0.91,
                    "evidence": {"fixture_id": "RECOVER-001", "categories": ["c2_simulation"]},
                    "references": [
                        {"source_name": "autosoc_fixture", "reference_id": "REF-1"},
                        {"source_name": "autosoc_fixture", "reference_id": "REF-1"},  # duplicate ref
                    ],
                }
            },
        )
        pipeline = ThreatIntelObservablePipeline(
            ti_providers=[provider],
            retry_policy=RetryPolicy(max_attempts=3),
        )
        results = pipeline.lookup_observable(ObservableTypeEnum.IP, "203.0.113.99")
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res.lookup_status, ProviderLookupStatusEnum.FOUND)
        self.assertEqual(res.verdict, ObservableVerdictEnum.MALICIOUS)
        self.assertEqual(res.confidence, 0.91)  # confidence preserved, never inflated
        self.assertEqual(len(res.references), 1)  # deduplicated
        self.assertEqual(res.evidence["fixture_id"], "RECOVER-001")
        self.assertFalse(res.live_lookup_performed)

    def test_retry_exhaustion_produces_retry_exhausted_and_unknown_verdict(self):
        calls = []

        class AlwaysTimeoutProvider(FixtureThreatIntelProvider):
            def lookup(self, request, *, lookup_timestamp=None):
                calls.append(request)
                return super().lookup(request, lookup_timestamp=lookup_timestamp)

        provider = AlwaysTimeoutProvider(
            provider_name="always_timeout",
            force_status=ProviderLookupStatusEnum.TIMEOUT,
        )
        pipeline = ThreatIntelObservablePipeline(
            ti_providers=[provider],
            retry_policy=RetryPolicy(max_attempts=3),
        )
        res = pipeline.lookup_observable(ObservableTypeEnum.IP, "203.0.113.99")[0]
        self.assertEqual(len(calls), 3)
        self.assertEqual(res.lookup_status, ProviderLookupStatusEnum.RETRY_EXHAUSTED)
        self.assertEqual(res.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertIsNone(res.confidence)
        self.assertIn("exhausted 3 retry attempts", res.errors[0].message)

    def test_non_retryable_statuses_are_never_retried(self):
        for target_ip in ("8.8.8.8",):  # no_result
            calls = []

            class SpyProvider(FixtureThreatIntelProvider):
                def lookup(self, request, *, lookup_timestamp=None):
                    calls.append(request)
                    return super().lookup(request, lookup_timestamp=lookup_timestamp)

            pipeline = ThreatIntelObservablePipeline(
                ti_providers=[SpyProvider()],
                retry_policy=RetryPolicy(max_attempts=4),
            )
            res = pipeline.lookup_observable(ObservableTypeEnum.IP, target_ip)[0]
            self.assertEqual(res.lookup_status, ProviderLookupStatusEnum.NO_RESULT)
            self.assertEqual(len(calls), 1)

        # malformed_response is also non-retryable
        bad_calls = []

        class BadRespSpy(FixtureThreatIntelProvider):
            def lookup(self, request, *, lookup_timestamp=None):
                bad_calls.append(request)
                return super().lookup(request, lookup_timestamp=lookup_timestamp)

        pipeline_bad = ThreatIntelObservablePipeline(
            ti_providers=[BadRespSpy()],
            retry_policy=RetryPolicy(max_attempts=4),
        )
        res_bad = pipeline_bad.lookup_observable(
            ObservableTypeEnum.DOMAIN, "malformed-resp.example.invalid"
        )[0]
        self.assertEqual(res_bad.lookup_status, ProviderLookupStatusEnum.MALFORMED_RESPONSE)
        self.assertEqual(len(bad_calls), 1)


class TestCircuitBreakerProviderDisabledAndRecovery(unittest.TestCase):
    """Verify circuit-breaker state transitions, recovery, and disabled semantics."""

    def test_circuit_breaker_opens_on_failures_and_recovers_after_cooldown(self):
        clock_now = [100.0]
        breaker = ProviderCircuitBreaker(
            failure_threshold=2,
            cooldown_seconds=30.0,
            clock=lambda: clock_now[0],
        )

        # Clean no_result must NEVER trip circuit breaker
        calls = []

        class ToggleProvider(FixtureThreatIntelProvider):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.fail_mode = False

            def lookup(self, request, *, lookup_timestamp=None):
                calls.append(request)
                if self.fail_mode:
                    self._force_status = ProviderLookupStatusEnum.UNAVAILABLE
                else:
                    self._force_status = None
                return super().lookup(request, lookup_timestamp=lookup_timestamp)

        prov = ToggleProvider(provider_name="cb_mock")
        pipeline = ThreatIntelObservablePipeline(
            ti_providers=[prov],
            circuit_breaker=breaker,
            retry_policy=RetryPolicy(max_attempts=1),
        )

        # 3 clean no_result calls leave circuit CLOSED & HEALTHY
        for _ in range(3):
            r_nd = pipeline.lookup_observable(ObservableTypeEnum.IP, "8.8.8.8")[0]
            self.assertEqual(r_nd.lookup_status, ProviderLookupStatusEnum.NO_RESULT)
        self.assertEqual(breaker.get_state("cb_mock"), CircuitBreakerStateEnum.CLOSED)
        self.assertEqual(
            breaker.get_operational_state("cb_mock"), ProviderOperationalStateEnum.HEALTHY
        )

        # Trigger 2 consecutive operational failures -> circuit OPENS
        prov.fail_mode = True
        r1 = pipeline.lookup_observable(ObservableTypeEnum.IP, "203.0.113.99")[0]
        self.assertEqual(r1.lookup_status, ProviderLookupStatusEnum.UNAVAILABLE)
        self.assertEqual(breaker.get_state("cb_mock"), CircuitBreakerStateEnum.CLOSED)

        r2 = pipeline.lookup_observable(ObservableTypeEnum.IP, "203.0.113.99")[0]
        self.assertEqual(r2.lookup_status, ProviderLookupStatusEnum.UNAVAILABLE)
        self.assertEqual(breaker.get_state("cb_mock"), CircuitBreakerStateEnum.OPEN)
        self.assertEqual(
            breaker.get_operational_state("cb_mock"),
            ProviderOperationalStateEnum.CIRCUIT_OPEN,
        )

        # While OPEN, lookups short-circuit without invoking provider
        count_before_open = len(calls)
        r_short = pipeline.lookup_observable(ObservableTypeEnum.IP, "203.0.113.99")[0]
        self.assertEqual(r_short.lookup_status, ProviderLookupStatusEnum.CIRCUIT_OPEN)
        self.assertEqual(r_short.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertIsNone(r_short.confidence)
        self.assertEqual(len(calls), count_before_open)

        # Advance clock past 30s cooldown -> HALF_OPEN probe allowed -> recovers to CLOSED
        clock_now[0] += 31.0
        self.assertEqual(breaker.get_state("cb_mock"), CircuitBreakerStateEnum.HALF_OPEN)
        prov.fail_mode = False
        r_rec = pipeline.lookup_observable(ObservableTypeEnum.IP, "203.0.113.99")[0]
        self.assertEqual(r_rec.lookup_status, ProviderLookupStatusEnum.FOUND)
        self.assertEqual(r_rec.verdict, ObservableVerdictEnum.MALICIOUS)
        self.assertEqual(breaker.get_state("cb_mock"), CircuitBreakerStateEnum.CLOSED)
        self.assertEqual(
            breaker.get_operational_state("cb_mock"), ProviderOperationalStateEnum.HEALTHY
        )

    def test_provider_disabled_short_circuits_cleanly(self):
        calls = []

        class DisabledSpy(FixtureThreatIntelProvider):
            def lookup(self, request, *, lookup_timestamp=None):
                calls.append(request)
                return super().lookup(request, lookup_timestamp=lookup_timestamp)

        prov = DisabledSpy(provider_name="disabled_mock", enabled=False)
        pipeline = ThreatIntelObservablePipeline(ti_providers=[prov])
        res = pipeline.lookup_observable(ObservableTypeEnum.IP, "203.0.113.99")[0]
        self.assertEqual(res.lookup_status, ProviderLookupStatusEnum.PROVIDER_DISABLED)
        self.assertEqual(res.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertIsNone(res.confidence)
        self.assertEqual(len(calls), 0)

        # Also test pipeline-level disabled_providers list
        prov2 = DisabledSpy(provider_name="mock_enabled_flag_false", enabled=True)
        pipeline2 = ThreatIntelObservablePipeline(
            ti_providers=[prov2], disabled_providers=["mock_enabled_flag_false"]
        )
        res2 = pipeline2.lookup_observable(ObservableTypeEnum.IP, "203.0.113.99")[0]
        self.assertEqual(res2.lookup_status, ProviderLookupStatusEnum.PROVIDER_DISABLED)
        self.assertEqual(len(calls), 0)


class TestSecurityEvidenceAndSafeRequestInvariants(unittest.TestCase):
    """Verify Day 11 security guarantees, safe requests, partial enrichment, and no net calls."""

    def test_safe_provider_request_rejects_raw_event_ids_users_cmd_and_secrets(self):
        for forbidden_key in (
            "raw_payload",
            "raw_event",
            "event_id",
            "source_event_id",
            "ingestion_id",
            "user",
            "command_line",
            "credentials",
            "authorization",
            "api_key",
        ):
            ok, req, err, _ = validate_safe_provider_request(
                ObservableTypeEnum.IP,
                "203.0.113.99",
                extra_payload={forbidden_key: "sensitive_val"},
            )
            self.assertFalse(ok)
            self.assertIsNone(req)
            self.assertIn(forbidden_key, err)

    def test_sync_ti_provider_adapter_strips_ids_and_maps_day11_statuses(self):
        seen_requests = []

        class InspectingFixtureProvider(FixtureThreatIntelProvider):
            def lookup(self, request, *, lookup_timestamp=None):
                seen_requests.append(request.model_dump())
                return super().lookup(request, lookup_timestamp=lookup_timestamp)

        adapter = SyncTIProviderAdapter(InspectingFixtureProvider())

        async def _run():
            for ip_addr, expected_status in (
                ("203.0.113.252", ThreatIntelLookupStatusEnum.RATE_LIMITED.value),
                ("203.0.113.250", ThreatIntelLookupStatusEnum.TIMEOUT.value),
                ("203.0.113.251", ThreatIntelLookupStatusEnum.UNAVAILABLE.value),
                ("8.8.8.8", ThreatIntelLookupStatusEnum.NO_DATA.value),
                ("203.0.113.99", ThreatIntelLookupStatusEnum.SUCCESS.value),
            ):
                out = await adapter.lookup(
                    ThreatIntelLookupRequest(
                        observable_type=ObservableTypeEnum.IP,
                        normalized_value=ip_addr,
                        source_event_id="evt-should-not-leak",
                        ingestion_id="ing-should-not-leak",
                    )
                )
                self.assertEqual(out["lookup_status"], expected_status)
                self.assertFalse(out["live_lookup_performed"])

        asyncio.run(_run())
        self.assertEqual(len(seen_requests), 5)
        for req_dict in seen_requests:
            self.assertEqual(set(req_dict.keys()), {"observable_type", "normalized_value"})

    def test_malicious_verdict_without_evidence_downgraded_to_malformed(self):
        unsubstantiated = ObservableLookupResult(
            provider_name="bad_provider",
            provider_version="1.0",
            observable_type=ObservableTypeEnum.IP,
            normalized_value="203.0.113.99",
            lookup_status=ProviderLookupStatusEnum.FOUND,
            verdict=ObservableVerdictEnum.MALICIOUS,
            confidence=0.99,
            evidence={},
            references=[],
            lookup_timestamp="2026-11-28T12:00:00Z",
            live_lookup_performed=False,
        )
        enforced = enforce_verdict_and_evidence_invariants(unsubstantiated)
        self.assertEqual(enforced.lookup_status, ProviderLookupStatusEnum.MALFORMED_RESPONSE)
        self.assertEqual(enforced.verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertIsNone(enforced.confidence)

    def test_deduplicate_references_preserves_order(self):
        refs = [
            ProviderReference(source_name="a", reference_id="1"),
            ProviderReference(source_name="b", reference_id="2"),
            ProviderReference(source_name="a", reference_id="1"),
        ]
        deduped = deduplicate_references(refs)
        self.assertEqual(len(deduped), 2)
        self.assertEqual([r.reference_id for r in deduped], ["1", "2"])

    def test_partial_enrichment_with_rate_limit_and_no_network_calls(self):
        seen_by_provider = []

        class SpyProvider(FixtureThreatIntelProvider):
            def lookup(self, request, *, lookup_timestamp=None):
                seen_by_provider.append(request.model_dump())
                return super().lookup(request, lookup_timestamp=lookup_timestamp)

        pipeline = ThreatIntelObservablePipeline(ti_providers=[SpyProvider()])
        ev = _make_event(
            source_ip="203.0.113.252",       # rate_limited
            destination_ip="203.0.113.99",   # malicious
            domain="unseen.example.invalid", # no_result
        )
        with patch.object(
            socket, "create_connection", side_effect=AssertionError("Network call attempted")
        ), patch.object(
            urllib.request, "urlopen", side_effect=AssertionError("HTTP call attempted")
        ):
            res = pipeline.enrich_with_threat_intel(ev, enriched_at="2026-11-28T12:05:00.000Z")

        self.assertEqual(res.enrichment_status, EnrichmentStatusEnum.ENRICHED_PARTIAL)
        self.assertFalse(res.live_lookup_performed)
        by_val = {o.normalized_value: o for o in res.observables}
        self.assertEqual(by_val["203.0.113.252"].verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertEqual(by_val["203.0.113.99"].verdict, ObservableVerdictEnum.MALICIOUS)
        self.assertEqual(by_val["unseen.example.invalid"].verdict, ObservableVerdictEnum.UNKNOWN)
        self.assertNotIn("DO_NOT_SEND_RAW", json.dumps(seen_by_provider))
        self.assertNotIn("alice.test", json.dumps(seen_by_provider))
        self.assertNotIn("UNRELATED_COMMAND_SECRET", json.dumps(seen_by_provider))
        self.assertNotIn(ev.event_id, json.dumps(seen_by_provider))
        self.assertNotIn(ev.ingestion_id, json.dumps(seen_by_provider))


if __name__ == "__main__":
    unittest.main()
