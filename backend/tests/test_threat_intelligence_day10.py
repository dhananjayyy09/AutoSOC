"""
AutoSOC Day 10 Tests - Threat Intelligence Provider Foundation & Integration
============================================================================
Covers:
  1. Provider configuration validation & offline deterministic fallback
  2. Built-in VirusTotal / AbuseIPDB / Generic adapters with httpx mocking & secret scrubbing
  3. Provider timeout, unavailable, and malformed/unsafe response handling
  4. TTL cache key binding, cache hit/expiry, rejection of invalid responses, Redis fallback
  5. Single-flight concurrent duplicate lookup protection & per-event observable cap
  6. Safe verdict invariants (never turning unknown -> malicious without evidence)
  7. Service + API + Retry + Raw/Normalized immutability (in-memory & live PostgreSQL)
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from main import app
from app.core.config import Settings, settings
from app.db.session import get_db
from app.events.enrichment_service import DeterministicLocalEnricher, EnrichmentService
from app.events.models import EventEnrichment, NormalizedEvent, RawEventEnvelope
from app.events.validation import compute_raw_hash
from app.threat_intelligence import (
    AbuseIPDBProvider,
    DeterministicEventEnricher,
    EnrichmentStatusEnum,
    ObservableTypeEnum,
    ObservableVerdictEnum,
    ThreatIntelCache,
    ThreatIntelLookupRequest,
    ThreatIntelLookupResult,
    ThreatIntelLookupStatusEnum,
    ThreatIntelOrchestrator,
    VirusTotalProvider,
    build_ti_cache_key,
)
from tests.test_enrichment_foundation import InMemoryDay9Session, _sample_norm_event

client = TestClient(app)


class StubTIProvider:
    """Deterministic async mock TI provider tracking exact invocation count."""

    def __init__(
        self,
        *,
        provider_id: str = "stub_ti",
        provider_version: str = "1.0.0",
        supported_types=(ObservableTypeEnum.IP, ObservableTypeEnum.DOMAIN, ObservableTypeEnum.URL, ObservableTypeEnum.FILE_HASH),
        configured: bool = True,
        delay_seconds: float = 0.0,
        response_factory=None,
        exception_to_raise: BaseException | None = None,
        secrets=(),
    ) -> None:
        self._provider_id = provider_id
        self._provider_version = provider_version
        self._supported = frozenset(supported_types)
        self._configured = configured
        self._delay = delay_seconds
        self._response_factory = response_factory
        self._exception = exception_to_raise
        self._secrets = list(secrets)
        self.calls: List[ThreatIntelLookupRequest] = []

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def provider_version(self) -> str:
        return self._provider_version

    def supports_observable(self, observable_type: ObservableTypeEnum) -> bool:
        return observable_type in self._supported

    def is_configured(self) -> bool:
        return self._configured

    def secret_values(self) -> List[str]:
        return list(self._secrets)

    async def lookup(self, request: ThreatIntelLookupRequest) -> Dict[str, Any]:
        self.calls.append(request)
        if self._delay > 0:
            await asyncio.sleep(self._delay)
        if self._exception is not None:
            raise self._exception
        if self._response_factory is not None:
            return self._response_factory(request)
        return {
            "provider": self._provider_id,
            "provider_version": self._provider_version,
            "observable_type": request.observable_type.value,
            "normalized_value": request.normalized_value,
            "lookup_status": ThreatIntelLookupStatusEnum.SUCCESS.value,
            "verdict": ObservableVerdictEnum.SUSPICIOUS.value,
            "confidence": 0.72,
            "score": 72,
            "categories": ["scanner"],
            "evidence": f"{self._provider_id} observed repeated probing",
            "lookup_timestamp": "2026-11-27T10:00:00Z",
            "live_lookup_performed": True,
        }


# ---------------------------------------------------------------------------
# 1. Configuration & Offline Fallback
# ---------------------------------------------------------------------------


def test_ti_configuration_defaults_and_validation():
    s = Settings()
    assert s.TI_ENABLED is False
    assert s.enabled_ti_providers == []
    assert s.TI_TIMEOUT_SECONDS == 3.0
    assert s.TI_CACHE_TTL_SECONDS == 300
    assert s.TI_MAX_OBSERVABLES_PER_EVENT == 10

    s_enabled = Settings(
        TI_ENABLED=True,
        TI_PROVIDERS=" VirusTotal , abuseipdb , VIRUSTOTAL ",
        TI_VIRUSTOTAL_API_KEY="super-secret-vt-key",
    )
    assert s_enabled.enabled_ti_providers == ["virustotal", "abuseipdb"]
    assert "super-secret-vt-key" not in repr(s_enabled)

    with pytest.raises(ValidationError):
        Settings(TI_TIMEOUT_SECONDS=0)
    with pytest.raises(ValidationError):
        Settings(TI_CACHE_TTL_SECONDS=0)
    with pytest.raises(ValidationError):
        Settings(TI_MAX_OBSERVABLES_PER_EVENT=0)
    with pytest.raises(ValidationError):
        Settings(TI_PROVIDERS="virustotal; DROP TABLE")
    with pytest.raises(ValidationError):
        Settings(TI_GENERIC_BASE_URL="ftp://invalid-scheme.example")
    with pytest.raises(ValidationError):
        Settings(TI_GENERIC_BASE_URL="https://user:pass@ti.example.com")


def test_offline_mode_when_ti_disabled_or_unconfigured():
    async def _run():
        # TI disabled -> deterministic offline mode, stub never called
        stub = StubTIProvider()
        orch_disabled = ThreatIntelOrchestrator(
            enabled=False,
            provider_names=["stub_ti"],
            cache=ThreatIntelCache(ttl_seconds=60, use_redis=False),
            providers={"stub_ti": stub},
        )
        enricher = DeterministicLocalEnricher(ti_orchestrator=orch_disabled)
        norm_dict = {
            "event_id": "aaaa1111-1111-4111-8111-111111111111",
            "ingestion_id": "bbbb1111-1111-4111-8111-111111111111",
            "source_ip": "198.51.100.42",
            "metadata": {},
        }
        res = await enricher.enrich(norm_dict)
        assert len(stub.calls) == 0
        assert res["status"] == "enriched"
        assert res["live_lookup_performed"] is False
        obs = res["enrichment_data"]["observables"][0]
        assert obs["verdict"] == "unknown"
        assert obs["lookup_status"] == "offline_only"

        # TI enabled, but provider missing credentials -> non-blocking warning, still unknown
        unconfigured = StubTIProvider(provider_id="virustotal", configured=False)
        orch_unconf = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["virustotal"],
            cache=ThreatIntelCache(ttl_seconds=60, use_redis=False),
            providers={"virustotal": unconfigured},
        )
        res2 = await DeterministicLocalEnricher(ti_orchestrator=orch_unconf).enrich(norm_dict)
        assert len(unconfigured.calls) == 0
        assert res2["status"] == "enriched_partial"
        assert res2["live_lookup_performed"] is False
        assert any("missing credentials" in w for w in res2["warnings"])
        assert res2["enrichment_data"]["observables"][0]["verdict"] == "unknown"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 2. Timeouts, Unavailable, Invalid Provider Data & Verdict Safety
# ---------------------------------------------------------------------------


def test_provider_timeout_unavailable_and_malformed_responses_do_not_cache_or_corrupt():
    async def _run():
        clock_now = [100.0]
        cache = ThreatIntelCache(ttl_seconds=60, use_redis=False, clock=lambda: clock_now[0])

        # Slow provider -> hits timeout cleanly without failing event enrichment
        slow = StubTIProvider(provider_id="slow_ti", delay_seconds=0.25)
        orch_timeout = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["slow_ti"],
            timeout_seconds=0.05,
            cache=cache,
            providers={"slow_ti": slow},
        )
        res_to = await DeterministicLocalEnricher(ti_orchestrator=orch_timeout).enrich(
            {
                "event_id": "11111111-1111-4111-8111-111111111111",
                "ingestion_id": "22222222-1111-4111-8111-111111111111",
                "source_ip": "198.51.100.90",
                "metadata": {},
            }
        )
        assert res_to["status"] == "enriched_partial"
        assert res_to["live_lookup_performed"] is False
        assert res_to["enrichment_data"]["observables"][0]["lookup_status"] == "timeout"
        assert res_to["enrichment_data"]["observables"][0]["verdict"] == "unknown"
        assert await cache.get(
            provider="slow_ti",
            observable_type=ObservableTypeEnum.IP,
            normalized_value="198.51.100.90",
        ) is None

        # Unavailable provider with secret inside exception -> secret scrubbed, never cached
        secret_tok = "SECRET_TI_TOKEN_XYZ987"
        unavail = StubTIProvider(
            provider_id="down_ti",
            exception_to_raise=ConnectionError(f"gateway rejected Bearer {secret_tok}"),
            secrets=[secret_tok],
        )
        orch_down = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["down_ti"],
            cache=cache,
            providers={"down_ti": unavail},
        )
        res_down = await DeterministicLocalEnricher(ti_orchestrator=orch_down).enrich(
            {
                "event_id": "33333333-1111-4111-8111-111111111111",
                "ingestion_id": "44444444-1111-4111-8111-111111111111",
                "domain": "down.example.invalid",
                "metadata": {},
            }
        )
        serialized = json.dumps(res_down)
        assert secret_tok not in serialized
        assert res_down["enrichment_data"]["observables"][0]["lookup_status"] == "unavailable"
        assert res_down["enrichment_data"]["observables"][0]["verdict"] == "unknown"

        # Untrusted malformed verdicts: malicious WITHOUT evidence + raw_payload key leak
        no_evidence = StubTIProvider(
            provider_id="bad_ti",
            response_factory=lambda req: {
                "provider": "bad_ti",
                "provider_version": "1.0",
                "observable_type": req.observable_type.value,
                "normalized_value": req.normalized_value,
                "lookup_status": "success",
                "verdict": "malicious",
                "evidence": "",
                "lookup_timestamp": "2026-11-27T10:00:00Z",
            },
        )
        raw_leak = StubTIProvider(
            provider_id="leak_ti",
            response_factory=lambda req: {
                "provider": "leak_ti",
                "provider_version": "1.0",
                "observable_type": req.observable_type.value,
                "normalized_value": req.normalized_value,
                "lookup_status": "success",
                "verdict": "benign",
                "evidence": "ok",
                "attributes": {"raw_payload": "LEAKED"},
                "lookup_timestamp": "2026-11-27T10:00:00Z",
            },
        )
        orch_bad = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["bad_ti", "leak_ti"],
            cache=cache,
            providers={"bad_ti": no_evidence, "leak_ti": raw_leak},
        )
        res_bad = await DeterministicLocalEnricher(ti_orchestrator=orch_bad).enrich(
            {
                "event_id": "55555555-1111-4111-8111-111111111111",
                "ingestion_id": "66666666-1111-4111-8111-111111111111",
                "domain": "untrusted.example.invalid",
                "metadata": {},
            }
        )
        assert res_bad["status"] == "enriched_partial"
        assert res_bad["enrichment_data"]["observables"][0]["verdict"] == "unknown"
        assert res_bad["enrichment_data"]["observables"][0]["lookup_status"] == "invalid_response"
        assert "raw_payload" not in json.dumps(res_bad)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 3. Cache Key Isolation, TTL Expiry, Redis Fallback, Single-Flight & Cap
# ---------------------------------------------------------------------------


def test_cache_ttl_expiry_key_isolation_and_singleflight_concurrency():
    async def _run():
        clock_now = [1000.0]
        cache = ThreatIntelCache(ttl_seconds=60, use_redis=False, clock=lambda: clock_now[0])

        # Key binds type + value distinctly
        k_ip = build_ti_cache_key("vt", ObservableTypeEnum.IP, "198.51.100.1")
        k_dom = build_ti_cache_key("vt", ObservableTypeEnum.DOMAIN, "198.51.100.1")
        assert k_ip != k_dom
        assert ":ip:198.51.100.1" in k_ip

        provider = StubTIProvider(provider_id="vt", delay_seconds=0.04)
        orch = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["vt"],
            cache=cache,
            providers={"vt": provider},
        )
        det = DeterministicEventEnricher()

        # Simulate 6 concurrent requests for the SAME observable -> exactly 1 provider call
        event_payload = {
            "event_id": "77777777-1111-4111-8111-111111111111",
            "ingestion_id": "88888888-1111-4111-8111-111111111111",
            "source_ip": "198.51.100.55",
            "destination_ip": "198.51.100.55",  # duplicate within event also suppressed
            "metadata": {},
        }
        base_obs = det.enrich_event(event_payload).observables
        assert len(base_obs) == 1  # deduplicated within event

        outcomes = await asyncio.gather(
            *(
                orch.enrich_observables(
                    base_obs,
                    ingestion_id=event_payload["ingestion_id"],
                    source_event_id=event_payload["event_id"],
                )
                for _ in range(6)
            )
        )
        assert len(provider.calls) == 1
        assert all(o.observables[0].verdict == ObservableVerdictEnum.SUSPICIOUS for o in outcomes)

        # Next call within TTL hits cache without calling provider
        cached_outcome = await orch.enrich_observables(
            base_obs,
            ingestion_id=event_payload["ingestion_id"],
            source_event_id=event_payload["event_id"],
        )
        assert len(provider.calls) == 1
        assert cached_outcome.cache_hits == 1
        assert cached_outcome.live_lookup_performed is False
        assert cached_outcome.observables[0].lookup_status == "cache_hit"

        # Advance monotonic clock past 60s TTL -> expires cache and executes fresh lookup
        clock_now[0] += 61.0
        refreshed = await orch.enrich_observables(
            base_obs,
            ingestion_id=event_payload["ingestion_id"],
            source_event_id=event_payload["event_id"],
        )
        assert len(provider.calls) == 2
        assert refreshed.live_lookup_performed is True
        assert refreshed.observables[0].lookup_status == "success"

    asyncio.run(_run())


def test_redis_cache_roundtrip_and_graceful_fallback_on_redis_error():
    async def _run():
        redis_store: Dict[str, str] = {}
        mock_redis = AsyncMock()
        mock_redis.get.side_effect = lambda k: redis_store.get(k)
        mock_redis.setex.side_effect = lambda k, ttl, val: redis_store.__setitem__(k, val)

        cache1 = ThreatIntelCache(
            ttl_seconds=120,
            use_redis=True,
            redis_client_getter=lambda: mock_redis,
        )
        ok = await cache1.set(
            ThreatIntelLookupResult(
                provider="virustotal",
                provider_version="v3",
                observable_type=ObservableTypeEnum.DOMAIN,
                normalized_value="bad.example.invalid",
                lookup_status=ThreatIntelLookupStatusEnum.SUCCESS,
                verdict=ObservableVerdictEnum.MALICIOUS,
                confidence=0.95,
                evidence="5 engines flagged",
                lookup_timestamp="2026-11-27T10:00:00Z",
                live_lookup_performed=True,
            )
        )
        assert ok is True
        assert len(redis_store) == 1

        # Fresh cache instance with empty memory reads directly from Redis
        cache2 = ThreatIntelCache(
            ttl_seconds=120,
            use_redis=True,
            redis_client_getter=lambda: mock_redis,
        )
        hit = await cache2.get(
            provider="virustotal",
            observable_type=ObservableTypeEnum.DOMAIN,
            normalized_value="bad.example.invalid",
        )
        assert hit is not None
        assert hit.cache_hit is True
        assert hit.verdict == ObservableVerdictEnum.MALICIOUS

        # Broken Redis fails closed on Redis tier and falls back cleanly to in-memory
        broken_redis = AsyncMock()
        broken_redis.get.side_effect = ConnectionError("redis down")
        broken_redis.setex.side_effect = ConnectionError("redis down")
        cache3 = ThreatIntelCache(
            ttl_seconds=120,
            use_redis=True,
            redis_client_getter=lambda: broken_redis,
        )
        assert await cache3.set(
            ThreatIntelLookupResult(
                provider="abuseipdb",
                provider_version="v2",
                observable_type=ObservableTypeEnum.IP,
                normalized_value="198.51.100.77",
                lookup_status=ThreatIntelLookupStatusEnum.SUCCESS,
                verdict=ObservableVerdictEnum.BENIGN,
                confidence=0.9,
                evidence="Verified clean",
                lookup_timestamp="2026-11-27T10:00:00Z",
            )
        )
        hit3 = await cache3.get(
            provider="abuseipdb",
            observable_type=ObservableTypeEnum.IP,
            normalized_value="198.51.100.77",
        )
        assert hit3 is not None and hit3.verdict == ObservableVerdictEnum.BENIGN

    asyncio.run(_run())


def test_max_observables_cap_enforced():
    async def _run():
        stub = StubTIProvider(provider_id="cap_ti")
        orch = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["cap_ti"],
            max_observables_per_event=2,
            cache=ThreatIntelCache(ttl_seconds=60, use_redis=False),
            providers={"cap_ti": stub},
        )
        res = await DeterministicLocalEnricher(ti_orchestrator=orch).enrich(
            {
                "event_id": "99999999-1111-4111-8111-111111111111",
                "ingestion_id": "aaaaaaaa-2222-4111-8111-111111111111",
                "source_ip": "198.51.100.1",
                "destination_ip": "10.0.0.5",
                "domain": "third.example.invalid",
                "file_hash": "sha256:" + ("c" * 64),
                "metadata": {},
            }
        )
        assert len(stub.calls) == 2
        statuses = [o["lookup_status"] for o in res["enrichment_data"]["observables"]]
        assert statuses[:2] == ["success", "success"]
        assert statuses[2:] == ["skipped_limit", "skipped_limit"]
        assert any("lookup cap (2)" in w for w in res["warnings"])

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 4. Built-in VirusTotal & AbuseIPDB Adapters (MockTransport)
# ---------------------------------------------------------------------------


def test_builtin_virustotal_and_abuseipdb_adapters_with_mock_http():
    async def _run():
        def vt_handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["x-apikey"] == "vt-secret-test"
            if request.url.path.endswith("/8.8.8.8"):
                return httpx.Response(
                    200,
                    json={
                        "data": {
                            "attributes": {
                                "last_analysis_stats": {
                                    "malicious": 4,
                                    "suspicious": 1,
                                    "harmless": 5,
                                    "undetected": 0,
                                },
                                "categories": {"EngineA": "c2"},
                            }
                        }
                    },
                )
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

        vt_transport = httpx.MockTransport(vt_handler)
        vt = VirusTotalProvider(api_key=SecretStr("vt-secret-test"))
        orig_async_client = httpx.AsyncClient

        with patch(
            "app.threat_intelligence.providers.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=vt_transport, *a, **kw),
        ):
            r_hit = await vt.lookup(
                ThreatIntelLookupRequest(
                    observable_type=ObservableTypeEnum.IP,
                    normalized_value="8.8.8.8",
                    ingestion_id="ing-vt-1",
                )
            )
            assert r_hit["lookup_status"] == "success"
            assert r_hit["verdict"] == "malicious"
            assert r_hit["score"] == 45
            assert r_hit["categories"] == ["c2"]

            r_404 = await vt.lookup(
                ThreatIntelLookupRequest(
                    observable_type=ObservableTypeEnum.DOMAIN,
                    normalized_value="unknown.example.invalid",
                    ingestion_id="ing-vt-2",
                )
            )
            assert r_404["lookup_status"] == "no_data"
            assert r_404["verdict"] == "unknown"

        abuse_transport = httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                json={
                    "data": {
                        "abuseConfidenceScore": 88,
                        "totalReports": 19,
                        "usageType": "Data Center",
                        "isp": "TestNet",
                        "countryCode": "US",
                        "isWhitelisted": False,
                    }
                },
            )
        )
        abuse = AbuseIPDBProvider(api_key=SecretStr("abuse-secret-test"))
        with patch(
            "app.threat_intelligence.providers.httpx.AsyncClient",
            side_effect=lambda *a, **kw: orig_async_client(transport=abuse_transport, *a, **kw),
        ):
            r_ab = await abuse.lookup(
                ThreatIntelLookupRequest(
                    observable_type=ObservableTypeEnum.IP,
                    normalized_value="198.51.100.77",
                    ingestion_id="ing-ab-1",
                )
            )
            assert r_ab["lookup_status"] == "success"
            assert r_ab["verdict"] == "malicious"
            assert r_ab["confidence"] == 0.88

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 5. Persistence Retry Preservation & Live PostgreSQL Integration
# ---------------------------------------------------------------------------


def test_retry_timeout_preserves_existing_valid_enrichment_data():
    async def _run():
        db = InMemoryDay9Session()
        norm = _sample_norm_event(
            event_id="bbbb1111-1111-4111-8111-111111111111",
            ingestion_id="cccc1111-1111-4111-8111-111111111111",
            source_ip="198.51.100.33",
        )
        db.normalized_rows.append(norm)

        # Initial Day 9/10 offline enrichment succeeds
        initial = await EnrichmentService().enrich_normalized_event(db, norm)
        assert initial is not None
        assert initial.enrichment_status == EnrichmentStatusEnum.ENRICHED.value
        saved_payload = dict(initial.enrichment_data)

        class TimeoutEnricher:
            PROVIDER_NAME = "timeout_ti"

            async def enrich(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
                raise asyncio.TimeoutError("upstream hung")

        # Manual retry hits full timeout -> MUST NOT erase existing enrichment_data
        retried = await EnrichmentService(enricher=TimeoutEnricher()).enrich_normalized_event(
            db, norm, retry=True
        )
        assert retried is not None
        assert retried.enrichment_id == initial.enrichment_id
        assert retried.attempt_count == 2
        assert retried.enrichment_data == saved_payload
        assert retried.enrichment_status == EnrichmentStatusEnum.ENRICHED_PARTIAL.value
        assert any("timeout" in e.lower() for e in retried.enrichment_errors)

    asyncio.run(_run())


_PG_DAY10_PREFIX = "day10-pg-test-"


def _make_nullpool_session_factory():
    engine = create_async_engine(settings.async_database_uri, poolclass=NullPool)
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )
    return engine, factory


async def _cleanup_day10_pg() -> None:
    engine, factory = _make_nullpool_session_factory()
    try:
        async with factory() as session:
            await session.execute(
                text(
                    "DELETE FROM event_enrichments WHERE event_id IN "
                    "(SELECT event_id FROM normalized_events WHERE sensor_id LIKE :p AND event_id IS NOT NULL)"
                ),
                {"p": f"{_PG_DAY10_PREFIX}%"},
            )
            await session.execute(
                delete(NormalizedEvent).where(
                    NormalizedEvent.sensor_id.like(f"{_PG_DAY10_PREFIX}%")
                )
            )
            await session.execute(
                delete(RawEventEnvelope).where(
                    RawEventEnvelope.sensor_id.like(f"{_PG_DAY10_PREFIX}%")
                )
            )
            await session.commit()
    finally:
        await engine.dispose()


@pytest.fixture()
def live_postgres_day10():
    async def _check():
        engine, factory = _make_nullpool_session_factory()
        try:
            async with factory() as session:
                await session.execute(text("SELECT 1 FROM event_enrichments LIMIT 1"))
        finally:
            await engine.dispose()
        await _cleanup_day10_pg()

    try:
        asyncio.run(_check())
    except Exception as exc:
        pytest.skip(f"Live PostgreSQL unavailable: {exc}")
        return

    pg_engine, pg_factory = _make_nullpool_session_factory()

    async def _override_pg_db():
        async with pg_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_pg_db
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_db, None)
        asyncio.run(pg_engine.dispose())
        asyncio.run(_cleanup_day10_pg())


def test_live_postgres_day10_ti_orchestration_cache_and_api_contract(live_postgres_day10):
    stub_vt = StubTIProvider(
        provider_id="virustotal",
        provider_version="v3",
        response_factory=lambda req: {
            "provider": "virustotal",
            "provider_version": "v3",
            "observable_type": req.observable_type.value,
            "normalized_value": req.normalized_value,
            "lookup_status": "success",
            "verdict": "malicious" if req.normalized_value == "198.51.100.200" else "benign",
            "confidence": 0.91 if req.normalized_value == "198.51.100.200" else 0.85,
            "score": 91 if req.normalized_value == "198.51.100.200" else 5,
            "categories": ["botnet"] if req.normalized_value == "198.51.100.200" else ["internal"],
            "evidence": "Mock VT intelligence match",
            "lookup_timestamp": "2026-11-27T10:30:00Z",
            "live_lookup_performed": True,
        },
    )
    orch = ThreatIntelOrchestrator(
        enabled=True,
        provider_names=["virustotal"],
        cache=ThreatIntelCache(ttl_seconds=120, use_redis=False),
        providers={"virustotal": stub_vt},
    )
    service_with_ti = EnrichmentService(enricher=DeterministicLocalEnricher(ti_orchestrator=orch))

    raw_obj = {
        "timestamp": "2026-11-27T10:30:00Z",
        "event_type": "alert",
        "src_ip": "198.51.100.200",
        "dest_ip": "10.0.0.50",
        "dest_port": 443,
        "proto": "tcp",
        "alert": {"severity": 1, "signature": "ET DAY10 TI TEST"},
        "dns": {"rrname": "c2.day10-test.invalid"},
    }
    raw_payload = json.dumps(raw_obj)

    with patch("app.api.v1.endpoints.events._default_enrichment_service", service_with_ti):
        resp = client.post(
            "/api/v1/events/ingest",
            json={
                "ingestion_id": str(uuid4()),
                "source_type": "suricata",
                "sensor_id": f"{_PG_DAY10_PREFIX}01",
                "ingest_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "raw_hash": compute_raw_hash(raw_payload),
                "raw_payload": raw_payload,
            },
        )
        assert resp.status_code == 201
        event_id = resp.json()["event_id"]
        assert resp.json()["enrichment_status"] == "enriched"

        # Verify normalized detail & enrichment detail preserve immutability + TI context
        norm_resp = client.get(f"/api/v1/events/normalized/{event_id}").json()
        assert norm_resp["source_ip"] == "198.51.100.200"
        assert norm_resp["enrichment"]["live_lookup_performed"] is True
        assert norm_resp["enrichment"]["context"]["threat_intel"]["ip_score"] == 91
        assert norm_resp["enrichment"]["context"]["threat_intel"]["providers_queried"] == ["virustotal"]

        by_val = {o["normalized_value"]: o for o in norm_resp["enrichment"]["observables"]}
        assert by_val["198.51.100.200"]["verdict"] == "malicious"
        assert by_val["198.51.100.200"]["confidence"] == 0.91
        assert by_val["198.51.100.200"]["lookup_status"] == "success"
        assert "raw_payload" not in norm_resp

        # Force retry immediately hits TTL cache (provider calls remain 3, not 6!)
        assert len(stub_vt.calls) == 3
        retry_resp = client.post(
            f"/api/v1/events/normalized/{event_id}/enrich",
            params={"force_retry": True},
        )
        assert retry_resp.status_code == 200
        r_body = retry_resp.json()
        assert r_body["attempt_count"] == 2
        assert r_body["enrichment_id"] == norm_resp["enrichment"]["enrichment_id"]
        assert len(stub_vt.calls) == 3
        assert r_body["context"]["threat_intel"]["cache_hits"] == 3
        assert r_body["observables"][0]["lookup_status"] == "cache_hit"


def test_conflicting_providers_resolve_to_unknown_in_orchestrator():
    from app.threat_intelligence import FixtureThreatIntelProvider, SyncTIProviderAdapter

    async def _run():
        p_mal = SyncTIProviderAdapter(
            FixtureThreatIntelProvider(
                provider_name="fixture_mal",
                fixtures={
                    ("ip", "203.0.113.99"): {
                        "verdict": "malicious",
                        "confidence": 0.9,
                        "evidence": {"categories": ["c2_simulation"], "fixture_id": "CONFLICT-MAL"},
                    }
                },
            )
        )
        p_benign = SyncTIProviderAdapter(
            FixtureThreatIntelProvider(
                provider_name="fixture_benign",
                fixtures={
                    ("ip", "203.0.113.99"): {
                        "verdict": "benign",
                        "confidence": 0.95,
                        "evidence": {"categories": ["allowlisted_simulation"], "fixture_id": "CONFLICT-BENIGN"},
                    }
                },
            )
        )
        orch = ThreatIntelOrchestrator(
            enabled=True,
            provider_names=["fixture_mal", "fixture_benign"],
            cache=ThreatIntelCache(ttl_seconds=60, use_redis=False),
            providers={"fixture_mal": p_mal, "fixture_benign": p_benign},
        )
        res = await DeterministicLocalEnricher(ti_orchestrator=orch).enrich(
            {
                "event_id": "eeee1111-1111-4111-8111-111111111111",
                "ingestion_id": "ffff1111-1111-4111-8111-111111111111",
                "source_ip": "203.0.113.99",
                "metadata": {},
            }
        )
        assert res["status"] == "enriched_partial"
        assert res["live_lookup_performed"] is False
        obs = res["enrichment_data"]["observables"][0]
        assert obs["verdict"] == "unknown"
        assert obs["confidence"] is None
        assert any("Conflicting provider verdicts" in w for w in res["warnings"])

    asyncio.run(_run())


def _run_fixture_scenarios_a_to_h(sensor_prefix: str) -> None:
    """
    Execute Scenarios A-H end-to-end through FastAPI endpoints using
    Pranjal's FixtureThreatIntelProvider bridged into DJ's unified orchestrator.
    """
    from app.threat_intelligence import build_configured_ti_providers

    fixture_settings = Settings(TI_ENABLED=True, TI_PROVIDERS="fixture")
    orch = ThreatIntelOrchestrator(
        settings_obj=fixture_settings,
        cache=ThreatIntelCache(ttl_seconds=120, use_redis=False),
        providers=build_configured_ti_providers(fixture_settings),
    )
    service = EnrichmentService(enricher=DeterministicLocalEnricher(ti_orchestrator=orch))

    def _post_suricata(sensor_suffix: str, raw_obj: Dict[str, Any]):
        raw_payload = json.dumps(raw_obj)
        return client.post(
            "/api/v1/events/ingest",
            json={
                "ingestion_id": str(uuid4()),
                "source_type": "suricata",
                "sensor_id": f"{sensor_prefix}{sensor_suffix}",
                "ingest_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "raw_hash": compute_raw_hash(raw_payload),
                "raw_payload": raw_payload,
            },
        )

    with patch("app.api.v1.endpoints.events._default_enrichment_service", service):
        # Scenario A & H: Successful fixture lookup + Day 9 network/indicator context preserved
        r_a = _post_suricata(
            "scen-a",
            {
                "timestamp": "2026-11-28T10:00:00Z",
                "event_type": "alert",
                "src_ip": "203.0.113.99",
                "dest_ip": "198.51.100.10",
                "dest_port": 443,
                "proto": "tcp",
                "alert": {"severity": 1, "signature": "ET FIXTURE SCENARIO A"},
                "dns": {"rrname": "benign-cdn.example.invalid"},
            },
        )
        assert r_a.status_code == 201 and r_a.json()["enrichment_status"] == "enriched"
        eid_a = r_a.json()["event_id"]

        norm_a = client.get(f"/api/v1/events/normalized/{eid_a}").json()
        assert "raw_payload" not in norm_a and "raw_event" not in norm_a
        assert norm_a["enrichment"]["live_lookup_performed"] is False
        assert norm_a["enrichment"]["context"]["network"]["dst_port_well_known"] is True
        assert norm_a["enrichment"]["context"]["indicators"]["domain_tld"] == "invalid"
        ti_a = norm_a["enrichment"]["context"]["threat_intel"]
        assert ti_a["provider"] == "autosoc.mock_ti_fixture"
        assert ti_a["live_lookup_performed"] is False
        assert ti_a["status"] == "completed"
        obs_a = {o["normalized_value"]: o for o in norm_a["enrichment"]["observables"]}
        assert obs_a["203.0.113.99"]["verdict"] == "malicious"
        assert obs_a["203.0.113.99"]["confidence"] == 0.92
        assert obs_a["203.0.113.99"]["live_lookup_performed"] is False
        assert obs_a["203.0.113.99"]["references"][0]["reference_id"] == "FIXTURE-IP-001"
        assert obs_a["benign-cdn.example.invalid"]["verdict"] == "benign"

        # Scenario B: No provider result (8.8.8.8 -> no_data & verdict unknown)
        r_b = _post_suricata(
            "scen-b",
            {
                "timestamp": "2026-11-28T10:01:00Z",
                "event_type": "flow",
                "src_ip": "8.8.8.8",
                "proto": "udp",
            },
        )
        assert r_b.status_code == 201 and r_b.json()["enrichment_status"] == "enriched"
        enr_b = client.get(f"/api/v1/events/normalized/{r_b.json()['event_id']}/enrichment").json()
        assert enr_b["observables"][0]["lookup_status"] == "no_data"
        assert enr_b["observables"][0]["verdict"] == "unknown"
        assert enr_b["observables"][0]["confidence"] is None
        assert enr_b["context"]["threat_intel"]["status"] == "no_result"

        # Scenario C & E: Provider unavailable + timeout mixed with valid observable -> enriched_partial
        r_c = _post_suricata(
            "scen-ce",
            {
                "timestamp": "2026-11-28T10:02:00Z",
                "event_type": "alert",
                "src_ip": "203.0.113.251",
                "dest_ip": "203.0.113.250",
                "dns": {"rrname": "malicious-sim.example.invalid"},
                "alert": {"severity": 2, "signature": "ET FIXTURE SCENARIO CE"},
            },
        )
        assert r_c.status_code == 201 and r_c.json()["enrichment_status"] == "enriched_partial"
        enr_c = client.get(f"/api/v1/events/normalized/{r_c.json()['event_id']}/enrichment").json()
        obs_c = {o["normalized_value"]: o for o in enr_c["observables"]}
        assert obs_c["203.0.113.251"]["lookup_status"] == "unavailable"
        assert obs_c["203.0.113.251"]["verdict"] == "unknown"
        assert obs_c["203.0.113.250"]["lookup_status"] == "timeout"
        assert obs_c["203.0.113.250"]["verdict"] == "unknown"
        assert obs_c["malicious-sim.example.invalid"]["verdict"] == "malicious"

        # Scenario F: No observables -> no_observables
        r_f = _post_suricata(
            "scen-f",
            {
                "timestamp": "2026-11-28T10:03:00Z",
                "event_type": "stats",
            },
        )
        assert r_f.status_code == 201 and r_f.json()["enrichment_status"] == "no_observables"

        # Scenario G: Normalization failure -> enrichment skipped
        bad_raw = json.dumps({"event_type": "alert"})
        r_g = client.post(
            "/api/v1/events/ingest",
            json={
                "ingestion_id": str(uuid4()),
                "source_type": "suricata",
                "sensor_id": f"{sensor_prefix}scen-g",
                "ingest_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "raw_hash": compute_raw_hash(bad_raw),
                "raw_payload": bad_raw,
            },
        )
        assert r_g.status_code == 201
        assert r_g.json()["normalization_status"] == "failed"
        assert r_g.json()["enrichment_status"] is None

        # Verify normalized list endpoint exposes batch enrichments and skipped status cleanly
        lst = client.get("/api/v1/events/normalized", params={"limit": 20}).json()
        assert lst["count"] >= 5
        assert any(it["enrichment_status"] == "skipped" for it in lst["items"])
        assert any(
            it["event_id"] == eid_a
            and it["enrichment"]["context"]["threat_intel"]["provider"] == "autosoc.mock_ti_fixture"
            for it in lst["items"]
        )


def test_fixture_provider_integration_all_scenarios_e2e_in_memory():
    db = InMemoryDay9Session()

    async def _override():
        yield db

    app.dependency_overrides[get_db] = _override
    try:
        _run_fixture_scenarios_a_to_h("day10-mem-")
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_fixture_provider_integration_all_scenarios_e2e_postgres(live_postgres_day10):
    """
    End-to-end PostgreSQL + API verification across Scenarios A-H using
    Pranjal's FixtureThreatIntelProvider bridged into DJ's unified orchestrator.
    """
    _run_fixture_scenarios_a_to_h(_PG_DAY10_PREFIX)
