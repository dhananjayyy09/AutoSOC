"""
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
"""

import asyncio
import json
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
