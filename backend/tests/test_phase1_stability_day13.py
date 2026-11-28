"""
AutoSOC Day 13 Tests - Phase 1 Backend Foundation & Integration Stability
=========================================================================
Deterministic verification of Phase 1 architecture, lifecycle, DI boundary,
and core contract stability without relying on accidental local state:
  1. Concurrent /ready probes & single-probe exception degradation without secret leakage
  2. Isolated lifespan shutdown teardown (failure in one closer never skips others)
  3. Clean FastAPI DI boundary on events router (get_normalization_service / get_enrichment_service)
  4. Public EnrichmentService.enricher accessor & TI status DI override compatibility
  5. Core endpoint error & contract checks using isolated create_app() (no global route pollution)
"""

import asyncio
import logging
import time
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from main import create_app
from app.api.v1.endpoints.events import (
    get_enrichment_service,
    get_normalization_service,
)
from app.core.lifespan import lifespan
from app.events.enrichment_service import (
    DeterministicLocalEnricher,
    EnrichmentService,
)
from app.events.normalization_service import NormalizationService
from app.threat_intelligence import ThreatIntelOrchestrator
from app.threat_intelligence.cache import ThreatIntelCache


def test_readiness_probes_execute_concurrently():
    """Verify /ready awaits Postgres, Redis, Qdrant, and Kafka concurrently."""
    isolated_app = create_app()

    async def _slow_ok():
        await asyncio.sleep(0.12)
        return True

    with patch("app.core.lifespan.init_db", new_callable=AsyncMock, return_value=True), \
         patch("app.core.lifespan.close_db", new_callable=AsyncMock), \
         patch("app.core.lifespan.redis_service.connect", new_callable=AsyncMock), \
         patch("app.core.lifespan.redis_service.close", new_callable=AsyncMock), \
         patch("app.core.lifespan.redis_service.check_health", new_callable=AsyncMock, return_value=True), \
         patch("app.core.lifespan.qdrant_service.connect", new_callable=AsyncMock), \
         patch("app.core.lifespan.qdrant_service.close", new_callable=AsyncMock), \
         patch("app.core.lifespan.qdrant_service.check_health", new_callable=AsyncMock, return_value=True), \
         patch("app.core.lifespan.kafka_service.connect", new_callable=AsyncMock), \
         patch("app.core.lifespan.kafka_service.close", new_callable=AsyncMock), \
         patch("app.core.lifespan.kafka_service.check_health", new_callable=AsyncMock, return_value=True), \
         patch("app.api.health.check_db_health", side_effect=_slow_ok), \
         patch("app.api.health.redis_service.check_health", side_effect=_slow_ok), \
         patch("app.api.health.qdrant_service.check_health", side_effect=_slow_ok), \
         patch("app.api.health.kafka_service.check_health", side_effect=_slow_ok):
        with TestClient(isolated_app) as client:
            start = time.perf_counter()
            resp = client.get("/ready")
            elapsed = time.perf_counter() - start

    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ok",
        "postgres": True,
        "redis": True,
        "qdrant": True,
        "kafka": True,
    }
    # Sequential execution of 4x 0.12s sleeps would exceed 0.48s
    assert elapsed < 0.35


def test_readiness_handles_probe_exception_safely(caplog):
    """If one readiness probe raises, /ready returns sanitized 503 without leaking exception text."""
    isolated_app = create_app()
    secret_uri = "postgresql+asyncpg://autosoc:super_secret_pw@localhost:5432/autosoc_db"

    with caplog.at_level(logging.WARNING, logger="autosoc"), \
         patch("app.core.lifespan.init_db", new_callable=AsyncMock, return_value=True), \
         patch("app.core.lifespan.close_db", new_callable=AsyncMock), \
         patch("app.core.lifespan.redis_service.connect", new_callable=AsyncMock), \
         patch("app.core.lifespan.redis_service.close", new_callable=AsyncMock), \
         patch("app.core.lifespan.redis_service.check_health", new_callable=AsyncMock, return_value=True), \
         patch("app.core.lifespan.qdrant_service.connect", new_callable=AsyncMock), \
         patch("app.core.lifespan.qdrant_service.close", new_callable=AsyncMock), \
         patch("app.core.lifespan.qdrant_service.check_health", new_callable=AsyncMock, return_value=True), \
         patch("app.core.lifespan.kafka_service.connect", new_callable=AsyncMock), \
         patch("app.core.lifespan.kafka_service.close", new_callable=AsyncMock), \
         patch("app.core.lifespan.kafka_service.check_health", new_callable=AsyncMock, return_value=True), \
         patch("app.api.health.check_db_health", side_effect=RuntimeError(secret_uri)), \
         patch("app.api.health.redis_service.check_health", new_callable=AsyncMock, return_value=True), \
         patch("app.api.health.qdrant_service.check_health", new_callable=AsyncMock, return_value=True), \
         patch("app.api.health.kafka_service.check_health", new_callable=AsyncMock, return_value=True):
        with TestClient(isolated_app) as client:
            resp = client.get("/ready")

    assert resp.status_code == 503
    assert resp.json()["detail"] == {
        "status": "degraded",
        "postgres": False,
        "redis": True,
        "qdrant": True,
        "kafka": True,
    }
    assert "super_secret_pw" not in resp.text
    joined_logs = "\n".join(r.message for r in caplog.records)
    assert "super_secret_pw" not in joined_logs


def test_lifespan_shutdown_isolates_closer_failures():
    """Failure closing one infrastructure client must not skip shutting down the remaining ones."""
    isolated_app = create_app()

    async def _run():
        with patch("app.core.lifespan.init_db", new_callable=AsyncMock, return_value=True), \
             patch("app.core.lifespan.close_db", new_callable=AsyncMock) as m_db_close, \
             patch("app.core.lifespan.redis_service.connect", new_callable=AsyncMock), \
             patch(
                 "app.core.lifespan.redis_service.close",
                 new_callable=AsyncMock,
                 side_effect=RuntimeError("redis close boom"),
             ) as m_r_close, \
             patch("app.core.lifespan.redis_service.check_health", new_callable=AsyncMock, return_value=True), \
             patch("app.core.lifespan.qdrant_service.connect", new_callable=AsyncMock), \
             patch("app.core.lifespan.qdrant_service.close", new_callable=AsyncMock) as m_q_close, \
             patch("app.core.lifespan.qdrant_service.check_health", new_callable=AsyncMock, return_value=True), \
             patch("app.core.lifespan.kafka_service.connect", new_callable=AsyncMock), \
             patch("app.core.lifespan.kafka_service.close", new_callable=AsyncMock) as m_k_close, \
             patch("app.core.lifespan.kafka_service.check_health", new_callable=AsyncMock, return_value=True):
            async with lifespan(isolated_app):
                pass
            m_r_close.assert_awaited_once()
            m_q_close.assert_awaited_once()
            m_k_close.assert_awaited_once()
            m_db_close.assert_awaited_once()

    asyncio.run(_run())


def test_events_di_dependencies_and_public_enricher_accessor():
    """Verify FastAPI DI overrides work cleanly for normalization/enrichment services."""
    isolated_app = create_app()
    custom_orch = ThreatIntelOrchestrator(
        enabled=False,
        provider_names=["virustotal"],
        timeout_seconds=1.5,
        cache=ThreatIntelCache(ttl_seconds=60, use_redis=False),
    )
    custom_enricher = DeterministicLocalEnricher(ti_orchestrator=custom_orch)
    custom_enrichment_svc = EnrichmentService(enricher=custom_enricher)
    custom_norm_svc = NormalizationService()

    assert custom_enrichment_svc.enricher is custom_enricher
    assert get_normalization_service() is not None
    assert get_enrichment_service() is not None

    isolated_app.dependency_overrides[get_normalization_service] = lambda: custom_norm_svc
    isolated_app.dependency_overrides[get_enrichment_service] = lambda: custom_enrichment_svc

    with patch("app.core.lifespan.init_db", new_callable=AsyncMock, return_value=True), \
         patch("app.core.lifespan.close_db", new_callable=AsyncMock), \
         patch("app.core.lifespan.redis_service.connect", new_callable=AsyncMock), \
         patch("app.core.lifespan.redis_service.close", new_callable=AsyncMock), \
         patch("app.core.lifespan.redis_service.check_health", new_callable=AsyncMock, return_value=True), \
         patch("app.core.lifespan.qdrant_service.connect", new_callable=AsyncMock), \
         patch("app.core.lifespan.qdrant_service.close", new_callable=AsyncMock), \
         patch("app.core.lifespan.qdrant_service.check_health", new_callable=AsyncMock, return_value=True), \
         patch("app.core.lifespan.kafka_service.connect", new_callable=AsyncMock), \
         patch("app.core.lifespan.kafka_service.close", new_callable=AsyncMock), \
         patch("app.core.lifespan.kafka_service.check_health", new_callable=AsyncMock, return_value=True):
        with TestClient(isolated_app) as client:
            ti_resp = client.get("/api/v1/events/threat-intelligence/providers")
            sys_resp = client.get("/api/v1/system/info")
            health_resp = client.get("/health")
            missing_resp = client.get("/api/v1/nonexistent-day13")

    assert ti_resp.status_code == 200
    ti_body = ti_resp.json()
    assert ti_body["policy"]["timeout_seconds"] == 1.5
    assert ti_body["policy"]["cache_ttl_seconds"] == 60
    assert sys_resp.status_code == 200
    assert sys_resp.json()["api_version"] == "v1"
    assert health_resp.status_code == 200
    assert health_resp.json() == {"status": "ok", "service": "autosoc-backend"}
    assert missing_resp.status_code == 404
    assert missing_resp.json() == {"message": "Not found"}
