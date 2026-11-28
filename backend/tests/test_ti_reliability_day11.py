"""
<<<<<<< HEAD
AutoSOC Day 11 Tests - TI Provider Reliability & Operational Observability
==========================================================================
Covers:
  1. Validated retry, exponential backoff, and circuit-breaker config settings
  2. Transient failure followed by successful retry (bounded exponential backoff)
  3. Retry exhaustion without infinite retries & without caching failures
  4. Rate-limit HTTP 429 Retry-After honoring (strictly capped at max_delay)
  5. Circuit breaker opening after repeated failures, short-circuiting, cooldown HALF_OPEN recovery, & health check recovery
  6. Provider timeout retries & preservation of existing valid EventEnrichment rows
  7. Permanent validation / malformed / auth 401 failures NOT retried
  8. Ordinary no_result (HTTP 404 / fixture miss) NOT retried & counts as reachable
  9. Disabled provider operational state & GET /api/v1/events/threat-intelligence/providers
 10. Sanitized operational diagnostics (no secrets, auth headers, or raw payloads leaked)
 11. Cache & persistence integrity under failure (no duplicate EventEnrichment rows)
=======
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
>>>>>>> origin/feature/pranjal/day11
"""

import asyncio
import json
<<<<<<< HEAD
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import patch
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from main import app
from app.core.config import Settings
from app.db.session import get_db
from app.events.enrichment_service import DeterministicLocalEnricher, EnrichmentService
from app.events.validation import compute_raw_hash
from app.threat_intelligence import (
    AbuseIPDBProvider,
    CircuitBreakerStateEnum,
    FixtureThreatIntelProvider,
    ObservableTypeEnum,
    ProviderFailureCategoryEnum,
    ProviderOperationalStateEnum,
    ProviderReliabilityPolicy,
    ProviderReliabilityTracker,
    SyncTIProviderAdapter,
    ThreatIntelCache,
    ThreatIntelLookupRequest,
    ThreatIntelOrchestrator,
    ThreatIntelProviderUnavailableError,
    VirusTotalProvider,
)
from tests.test_enrichment_foundation import InMemoryDay9Session

client = TestClient(app)


class ScriptedTIProvider:
    """Async test provider executing a scripted sequence of results or exceptions."""

    def __init__(
        self,
        *,
        provider_id: str = "scripted_ti",
        provider_version: str = "1.0.0",
        configured: bool = True,
        outcomes: List[Any] | None = None,
        delay_seconds: float = 0.0,
        secrets: List[str] | None = None,
    ) -> None:
        self._provider_id = provider_id
        self._provider_version = provider_version
        self._configured = configured
        self._outcomes = list(outcomes or [])
        self._delay = delay_seconds
        self._secrets = list(secrets or [])
        self.calls: List[ThreatIntelLookupRequest] = []

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def provider_version(self) -> str:
        return self._provider_version

    def supports_observable(self, observable_type: ObservableTypeEnum) -> bool:
        return True

    def is_configured(self) -> bool:
        return self._configured

    def secret_values(self) -> List[str]:
        return list(self._secrets)

    async def lookup(self, request: ThreatIntelLookupRequest) -> Dict[str, Any]:
        idx = len(self.calls)
        self.calls.append(request)
        if self._delay > 0:
            await asyncio.sleep(self._delay)
        outcome = self._outcomes[min(idx, len(self._outcomes) - 1)] if self._outcomes else {}
        if callable(outcome):
            outcome = outcome(request, idx)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _ok_result(provider_id: str, req: ThreatIntelLookupRequest, verdict: str = "suspicious") -> Dict[str, Any]:
    return {
        "provider": provider_id,
        "provider_version": "1.0.0",
        "observable_type": req.observable_type.value,
        "normalized_value": req.normalized_value,
        "lookup_status": "success",
        "verdict": verdict,
        "confidence": 0.8,
        "score": 80,
        "evidence": f"{provider_id} matched indicator",
        "lookup_timestamp": "2026-11-28T20:00:00Z",
        "live_lookup_performed": True,
    }


# ---------------------------------------------------------------------------
# 1. Settings & Policy Validation
# ---------------------------------------------------------------------------


def test_day11_reliability_settings_validation():
    s = Settings()
    assert s.TI_MAX_RETRIES == 2
    assert s.TI_RETRY_BASE_DELAY_SECONDS == 0.25
    assert s.TI_RETRY_MAX_DELAY_SECONDS == 5.0
    assert s.TI_CIRCUIT_BREAKER_THRESHOLD == 3
    assert s.TI_CIRCUIT_BREAKER_COOLDOWN_SECONDS == 60.0

    with pytest.raises(ValidationError):
        Settings(TI_MAX_RETRIES=-1)
    with pytest.raises(ValidationError):
        Settings(TI_MAX_RETRIES=6)
    with pytest.raises(ValidationError):
        Settings(TI_CIRCUIT_BREAKER_THRESHOLD=0)
    with pytest.raises(ValidationError):
        Settings(TI_CIRCUIT_BREAKER_COOLDOWN_SECONDS=0.5)
    with pytest.raises(ValidationError):
        Settings(TI_RETRY_BASE_DELAY_SECONDS=2.0, TI_RETRY_MAX_DELAY_SECONDS=1.0)


# ---------------------------------------------------------------------------
# 2. Transient Failure + Exponential Backoff + Success & Retry Exhaustion
# ---------------------------------------------------------------------------


def test_transient_failure_followed_by_successful_retry_and_backoff():
    async def _run():
        delays: List[float] = []

        async def fake_sleep(d: float) -> None:
            delays.append(d)

        cache = ThreatIntelCache(ttl_seconds=120, use_redis=False)
        provider = ScriptedTIProvider(
            provider_id="flaky_ti",
            outcomes=[
                ThreatIntelProviderUnavailableError("upstream 503", retryable=True),
                ConnectionError("transient reset"),
                lambda req, _: _ok_result("flaky_ti", req, verdict="malicious"),
            ],
        )
        policy = ProviderReliabilityPolicy(
            max_retries=2,
            retry_base_delay_seconds=0.25,
            retry_max_delay_seconds=1.0,
            circuit_breaker_threshold=3,
            circuit_breaker_cooldown_seconds=30.0,
        )
        orch = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["flaky_ti"],
            cache=cache,
            providers={"flaky_ti": provider},
            reliability_policy=policy,
            sleep_fn=fake_sleep,
        )
        res = await DeterministicLocalEnricher(ti_orchestrator=orch).enrich(
            {
                "event_id": "11111111-1111-4111-8111-111111111111",
                "ingestion_id": "22222222-1111-4111-8111-111111111111",
                "source_ip": "198.51.100.42",
                "metadata": {},
            }
        )
        assert len(provider.calls) == 3
        assert delays == [0.25, 0.5]
        assert res["status"] == "enriched"
        obs = res["enrichment_data"]["observables"][0]
        assert obs["verdict"] == "malicious"
        assert obs["lookup_status"] == "success"

        status_snap = orch.get_providers_status().providers[0]
        assert status_snap.operational_state == ProviderOperationalStateEnum.HEALTHY
        assert status_snap.circuit_state == CircuitBreakerStateEnum.CLOSED
        assert status_snap.consecutive_failures == 0
        assert status_snap.total_retries == 2
        assert status_snap.last_success_at is not None

        # Valid result WAS cached after retry recovered
        cached = await cache.get(
            provider="flaky_ti",
            observable_type=ObservableTypeEnum.IP,
            normalized_value="198.51.100.42",
        )
        assert cached is not None and cached.verdict.value == "malicious"

    asyncio.run(_run())


def test_retry_exhaustion_stops_cleanly_without_caching_failure():
    async def _run():
        delays: List[float] = []

        async def fake_sleep(d: float) -> None:
            delays.append(d)

        cache = ThreatIntelCache(ttl_seconds=120, use_redis=False)
        provider = ScriptedTIProvider(
            provider_id="down_ti",
            outcomes=[ThreatIntelProviderUnavailableError("502 Bad Gateway", retryable=True)],
        )
        policy = ProviderReliabilityPolicy(
            max_retries=2,
            retry_base_delay_seconds=0.5,
            retry_max_delay_seconds=0.75,
            circuit_breaker_threshold=3,
        )
        orch = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["down_ti"],
            cache=cache,
            providers={"down_ti": provider},
            reliability_policy=policy,
            sleep_fn=fake_sleep,
        )
        res = await DeterministicLocalEnricher(ti_orchestrator=orch).enrich(
            {
                "event_id": "33333333-1111-4111-8111-111111111111",
                "ingestion_id": "44444444-1111-4111-8111-111111111111",
                "source_ip": "198.51.100.43",
                "metadata": {},
            }
        )
        # 1 initial + 2 retries = 3 calls, backoff capped at retry_max_delay_seconds=0.75
        assert len(provider.calls) == 3
        assert delays == [0.5, 0.75]
        assert res["status"] == "enriched_partial"
        assert res["enrichment_data"]["observables"][0]["verdict"] == "unknown"
        assert res["enrichment_data"]["observables"][0]["lookup_status"] == "unavailable"

        # Failure is NOT cached
        assert (
            await cache.get(
                provider="down_ti",
                observable_type=ObservableTypeEnum.IP,
                normalized_value="198.51.100.43",
            )
            is None
        )

        st = orch.get_providers_status().providers[0]
        assert st.operational_state == ProviderOperationalStateEnum.DEGRADED
        assert st.consecutive_failures == 1
        assert st.total_failures == 1
        assert st.total_retries == 2
        assert st.last_failure_category == ProviderFailureCategoryEnum.UNAVAILABLE

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 3. Rate Limit Handling (HTTP 429 + Retry-After)
# ---------------------------------------------------------------------------


def test_rate_limit_http_429_retry_after_capped_and_recovers():
    async def _run():
        delays: List[float] = []
        attempts = {"n": 0}

        async def fake_sleep(d: float) -> None:
            delays.append(d)

        def vt_handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            if attempts["n"] == 1:
                return httpx.Response(429, headers={"Retry-After": "1.5"})
            if attempts["n"] == 2:
                return httpx.Response(429, headers={"Retry-After": "99999"})
            return httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 3,
                                "suspicious": 0,
                                "harmless": 7,
                                "undetected": 0,
                            }
                        }
                    }
                },
            )

        vt_transport = httpx.MockTransport(vt_handler)
        orig_async_client = httpx.AsyncClient
        vt = VirusTotalProvider(api_key=SecretStr("vt-rate-limit-secret"))
        policy = ProviderReliabilityPolicy(
            max_retries=2,
            retry_base_delay_seconds=0.1,
            retry_max_delay_seconds=2.5,
            circuit_breaker_threshold=3,
        )
        orch = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["virustotal"],
            cache=ThreatIntelCache(ttl_seconds=60, use_redis=False),
            providers={"virustotal": vt},
            reliability_policy=policy,
            sleep_fn=fake_sleep,
        )

        with patch(
            "app.threat_intelligence.providers.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=vt_transport, *a, **kw),
        ):
            res = await DeterministicLocalEnricher(ti_orchestrator=orch).enrich(
                {
                    "event_id": "55555555-1111-4111-8111-111111111111",
                    "ingestion_id": "66666666-1111-4111-8111-111111111111",
                    "source_ip": "198.51.100.77",
                    "metadata": {},
                }
            )

        assert attempts["n"] == 3
        # 1st Retry-After=1.5 respected; 2nd huge Retry-After=99999 capped at max_delay=2.5
        assert delays == [1.5, 2.5]
        assert res["enrichment_data"]["observables"][0]["verdict"] == "malicious"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. Circuit Breaker Open, Short-Circuit, Cooldown Recovery & Health Check
# ---------------------------------------------------------------------------


def test_circuit_breaker_opens_short_circuits_and_recovers_after_cooldown():
    async def _run():
        now = [100.0]

        async def no_sleep(_: float) -> None:
            return None

        # Succeeds ONLY on attempt index >= 3 (after 3 separate failing lookups open breaker)
        provider = ScriptedTIProvider(
            provider_id="cb_ti",
            outcomes=[
                ThreatIntelProviderUnavailableError("503", retryable=True),
                ThreatIntelProviderUnavailableError("503", retryable=True),
                ThreatIntelProviderUnavailableError("503", retryable=True),
                lambda req, _: _ok_result("cb_ti", req, verdict="benign"),
            ],
        )
        policy = ProviderReliabilityPolicy(
            max_retries=0,
            retry_base_delay_seconds=0.0,
            retry_max_delay_seconds=0.0,
            circuit_breaker_threshold=3,
            circuit_breaker_cooldown_seconds=30.0,
        )
        orch = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["cb_ti"],
            cache=ThreatIntelCache(ttl_seconds=60, use_redis=False),
            providers={"cb_ti": provider},
            reliability_policy=policy,
            sleep_fn=no_sleep,
            clock=lambda: now[0],
        )
        enricher = DeterministicLocalEnricher(ti_orchestrator=orch)

        # 3 repeated failures open the circuit breaker
        for i, ip in enumerate(("198.51.100.1", "198.51.100.2", "198.51.100.3")):
            res = await enricher.enrich(
                {
                    "event_id": f"0000000{i}-1111-4111-8111-111111111111",
                    "ingestion_id": f"1000000{i}-1111-4111-8111-111111111111",
                    "source_ip": ip,
                    "metadata": {},
                }
            )
            assert res["enrichment_data"]["observables"][0]["lookup_status"] == "unavailable"

        assert len(provider.calls) == 3
        st_open = orch.get_providers_status().providers[0]
        assert st_open.circuit_state == CircuitBreakerStateEnum.OPEN
        assert st_open.operational_state == ProviderOperationalStateEnum.UNAVAILABLE
        assert st_open.consecutive_failures == 3
        assert st_open.cooldown_remaining_seconds == 30.0

        # Next lookup BEFORE cooldown is short-circuited without calling provider
        now[0] += 10.0
        res_short = await enricher.enrich(
            {
                "event_id": "00000004-1111-4111-8111-111111111111",
                "ingestion_id": "10000004-1111-4111-8111-111111111111",
                "source_ip": "198.51.100.4",
                "metadata": {},
            }
        )
        assert len(provider.calls) == 3  # NO call issued!
        assert "circuit breaker open" in res_short["warnings"][0].lower()
        assert res_short["enrichment_data"]["observables"][0]["verdict"] == "unknown"

        # Advance clock past 30s cooldown -> status reflects half_open & next call probes
        now[0] += 25.0
        assert orch.get_providers_status().providers[0].circuit_state == CircuitBreakerStateEnum.HALF_OPEN
        assert orch.get_providers_status().providers[0].operational_state == ProviderOperationalStateEnum.DEGRADED

        res_rec = await enricher.enrich(
            {
                "event_id": "00000005-1111-4111-8111-111111111111",
                "ingestion_id": "10000005-1111-4111-8111-111111111111",
                "source_ip": "198.51.100.5",
                "metadata": {},
            }
        )
        assert len(provider.calls) == 4
        assert res_rec["status"] == "enriched"
        assert res_rec["enrichment_data"]["observables"][0]["verdict"] == "benign"
        st_closed = orch.get_providers_status().providers[0]
        assert st_closed.circuit_state == CircuitBreakerStateEnum.CLOSED
        assert st_closed.operational_state == ProviderOperationalStateEnum.HEALTHY
        assert st_closed.consecutive_failures == 0

        # Explicit health-check recovery works on an open circuit too
        orch.record_provider_health_check("cb_ti", healthy=False, error_summary="maintenance")
        orch.record_provider_health_check("cb_ti", healthy=False, error_summary="maintenance")
        orch.record_provider_health_check("cb_ti", healthy=False, error_summary="maintenance")
        assert orch.get_providers_status().providers[0].circuit_state == CircuitBreakerStateEnum.OPEN
        recovered = orch.record_provider_health_check("cb_ti", healthy=True)
        assert recovered.circuit_state == CircuitBreakerStateEnum.CLOSED
        assert recovered.operational_state == ProviderOperationalStateEnum.HEALTHY

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 5. Non-Retryable Conditions: Permanent Validation, Malformed, Auth, & No-Result
# ---------------------------------------------------------------------------


def test_permanent_validation_malformed_auth_and_no_result_never_retry():
    async def _run():
        async def fail_if_slept(_: float) -> None:
            raise AssertionError("Should not sleep/retry on non-transient outcomes")

        policy = ProviderReliabilityPolicy(
            max_retries=3,
            retry_base_delay_seconds=0.1,
            retry_max_delay_seconds=1.0,
            circuit_breaker_threshold=2,
        )

        # 1. Malformed provider response (malicious without evidence) -> 1 call, 0 retries
        malformed_p = ScriptedTIProvider(
            provider_id="malformed_ti",
            outcomes=[
                {
                    "provider": "malformed_ti",
                    "provider_version": "1.0.0",
                    "observable_type": "ip",
                    "normalized_value": "198.51.100.8",
                    "lookup_status": "success",
                    "verdict": "malicious",
                    "evidence": "",
                    "lookup_timestamp": "2026-11-28T20:00:00Z",
                }
            ],
        )
        orch_mal = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["malformed_ti"],
            cache=ThreatIntelCache(ttl_seconds=60, use_redis=False),
            providers={"malformed_ti": malformed_p},
            reliability_policy=policy,
            sleep_fn=fail_if_slept,
        )
        res_mal = await DeterministicLocalEnricher(ti_orchestrator=orch_mal).enrich(
            {
                "event_id": "aaaa1111-1111-4111-8111-111111111111",
                "ingestion_id": "bbbb1111-1111-4111-8111-111111111111",
                "source_ip": "198.51.100.8",
                "metadata": {},
            }
        )
        assert len(malformed_p.calls) == 1
        assert res_mal["enrichment_data"]["observables"][0]["lookup_status"] == "invalid_response"
        assert res_mal["enrichment_data"]["observables"][0]["verdict"] == "unknown"

        # 2. HTTP 401 non-transient auth failure -> 1 call, 0 retries
        abuse_transport = httpx.MockTransport(lambda req: httpx.Response(401))
        orig_async_client = httpx.AsyncClient
        abuse = AbuseIPDBProvider(api_key=SecretStr("bad-auth-key-SECRET"))
        orch_auth = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["abuseipdb"],
            cache=ThreatIntelCache(ttl_seconds=60, use_redis=False),
            providers={"abuseipdb": abuse},
            reliability_policy=policy,
            sleep_fn=fail_if_slept,
        )
        with patch(
            "app.threat_intelligence.providers.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=abuse_transport, *a, **kw),
        ):
            res_auth = await DeterministicLocalEnricher(ti_orchestrator=orch_auth).enrich(
                {
                    "event_id": "cccc1111-1111-4111-8111-111111111111",
                    "ingestion_id": "dddd1111-1111-4111-8111-111111111111",
                    "source_ip": "198.51.100.9",
                    "metadata": {},
                }
            )
        assert res_auth["enrichment_data"]["observables"][0]["lookup_status"] == "unavailable"
        assert orch_auth.get_providers_status().providers[0].total_retries == 0
        assert "bad-auth-key-SECRET" not in json.dumps(orch_auth.get_providers_status().model_dump())

        # 3. Fixture NO_RESULT -> 1 call, 0 retries, provider remains HEALTHY
        fixture_prov = SyncTIProviderAdapter(FixtureThreatIntelProvider())
        orch_fix = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["autosoc.mock_ti_fixture"],
            cache=ThreatIntelCache(ttl_seconds=60, use_redis=False),
            providers={"autosoc.mock_ti_fixture": fixture_prov},
            reliability_policy=policy,
            sleep_fn=fail_if_slept,
        )
        res_nr = await DeterministicLocalEnricher(ti_orchestrator=orch_fix).enrich(
            {
                "event_id": "eeee1111-1111-4111-8111-111111111111",
                "ingestion_id": "ffff1111-1111-4111-8111-111111111111",
                "source_ip": "8.8.8.8",
                "metadata": {},
            }
        )
        assert res_nr["status"] == "enriched"
        assert res_nr["enrichment_data"]["observables"][0]["lookup_status"] == "no_data"
        assert res_nr["enrichment_data"]["observables"][0]["verdict"] == "unknown"
        st_nr = orch_fix.get_providers_status().providers[0]
        assert st_nr.operational_state == ProviderOperationalStateEnum.HEALTHY
        assert st_nr.total_requests == 1 and st_nr.total_retries == 0

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 6. Provider Timeout, Operational Status API, Secret Scrubbing & Persistence Integrity
# ---------------------------------------------------------------------------


def test_provider_timeout_retry_cache_safety_and_single_persistence_record():
    async def _sleep_none(_: float) -> None:
        return None

    db = InMemoryDay9Session()

    async def _override():
        yield db

    cache = ThreatIntelCache(ttl_seconds=120, use_redis=False)
    timeout_provider = ScriptedTIProvider(
        provider_id="timeout_ti",
        delay_seconds=0.15,
        outcomes=[lambda req, _: _ok_result("timeout_ti", req)],
    )
    policy = ProviderReliabilityPolicy(
        max_retries=1,
        retry_base_delay_seconds=0.0,
        retry_max_delay_seconds=0.0,
        circuit_breaker_threshold=2,
    )
    orch = ThreatIntelOrchestrator(
        enabled=True,
        provider_names=["timeout_ti"],
        timeout_seconds=0.03,
        cache=cache,
        providers={"timeout_ti": timeout_provider},
        reliability_policy=policy,
        sleep_fn=_sleep_none,
    )
    service = EnrichmentService(enricher=DeterministicLocalEnricher(ti_orchestrator=orch))

    raw_obj = {
        "timestamp": "2026-11-28T20:10:00Z",
        "event_type": "alert",
        "src_ip": "198.51.100.66",
        "dest_ip": "10.0.0.10",
        "dest_port": 443,
        "proto": "tcp",
        "alert": {"severity": 2, "signature": "ET DAY11 TIMEOUT TEST"},
    }
    raw_str = json.dumps(raw_obj)
    app.dependency_overrides[get_db] = _override
    try:
        with patch("app.api.v1.endpoints.events._default_enrichment_service", service):
            ing = client.post(
                "/api/v1/events/ingest",
                json={
                    "ingestion_id": str(uuid4()),
                    "source_type": "suricata",
                    "sensor_id": "day11-timeout-01",
                    "ingest_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "raw_hash": compute_raw_hash(raw_str),
                    "raw_payload": raw_str,
                },
            )
            assert ing.status_code == 201
            assert ing.json()["enrichment_status"] == "enriched_partial"
            eid = ing.json()["event_id"]

            # Even though provider retried for both observables, ONLY ONE EventEnrichment row exists!
            assert len(db.enrichment_rows) == 1
            assert db.enrichment_rows[0].attempt_count == 1
            # Timed out lookups never enter cache
            assert asyncio.run(
                cache.get(
                    provider="timeout_ti",
                    observable_type=ObservableTypeEnum.IP,
                    normalized_value="198.51.100.66",
                )
            ) is None

            # Operational status endpoint reports timeout / degraded-open cleanly without leaking raw data
            status_resp = client.get("/api/v1/events/threat-intelligence/providers")
            assert status_resp.status_code == 200
            s_body = status_resp.json()
            assert s_body["ti_enabled"] is True
            assert s_body["policy"]["max_retries"] == 1
            p_status = next(p for p in s_body["providers"] if p["provider"] == "timeout_ti")
            assert p_status["last_failure_category"] == "timeout"
            assert p_status["circuit_state"] == "open"
            assert p_status["operational_state"] == "unavailable"
            assert "198.51.100.66" not in json.dumps(s_body)
            assert "ET DAY11 TIMEOUT TEST" not in json.dumps(s_body)
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_providers_status_endpoint_disabled_and_scrubs_secrets():
    secret_val = "SECRET_TOKEN_SHOULD_NOT_APPEAR"
    s = Settings(
        TI_ENABLED=True,
        TI_PROVIDERS="secret_ti",
        TI_VIRUSTOTAL_API_KEY=secret_val,
    )
    failing = ScriptedTIProvider(
        provider_id="secret_ti",
        outcomes=[ConnectionError(f"auth header Bearer {secret_val} failed")],
        secrets=[secret_val],
    )
    orch = ThreatIntelOrchestrator(
        settings_obj=s,
        cache=ThreatIntelCache(ttl_seconds=60, use_redis=False),
        providers={"secret_ti": failing},
        reliability_policy=ProviderReliabilityPolicy(
            max_retries=0, retry_base_delay_seconds=0.0, retry_max_delay_seconds=0.0
        ),
    )
    asyncio.run(
        DeterministicLocalEnricher(ti_orchestrator=orch).enrich(
            {
                "event_id": "99999999-1111-4111-8111-111111111111",
                "ingestion_id": "88888888-1111-4111-8111-111111111111",
                "source_ip": "198.51.100.123",
                "metadata": {},
            }
        )
    )
    service = EnrichmentService(enricher=DeterministicLocalEnricher(ti_orchestrator=orch))
    with patch("app.api.v1.endpoints.events._default_enrichment_service", service):
        r = client.get("/api/v1/events/threat-intelligence/providers")
    assert r.status_code == 200
    dumped = r.text
    assert secret_val not in dumped
    assert "[REDACTED]" in dumped

    # Disabled baseline reports disabled state safely
    disabled_resp = client.get("/api/v1/events/threat-intelligence/providers")
    assert disabled_resp.status_code == 200
    d_body = disabled_resp.json()
    assert d_body["ti_enabled"] is False
    assert all(p["operational_state"] == "disabled" for p in d_body["providers"])
=======
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
>>>>>>> origin/feature/pranjal/day11
