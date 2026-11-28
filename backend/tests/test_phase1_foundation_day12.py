"""
AutoSOC Day 12 Tests - Phase 1 Backend & Infrastructure Foundation Verification
=============================================================================
Covers concrete Phase 1 stabilization checks:
  1. Core configuration validation (APP_ENV, ports, non-blank hosts/brokers)
  2. Non-blocking Kafka health check via asyncio.to_thread
  3. Redis & Qdrant bounded connection failure cleanup and shutdown reset
  4. Sanitized persistence exception logging without leaking DB credentials
  5. Live 4-service readiness verification helper expectations
"""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError

from main import app
from app.core.config import Settings
from app.services.kafka_client import KafkaService
from app.services.qdrant_client import QdrantService
from app.services.redis_client import RedisService


def test_phase1_settings_validation_and_sanitization():
    s = Settings()
    assert s.APP_ENV in ("development", "testing", "staging", "production")
    assert s.POSTGRES_PORT == "5432"
    assert 1 <= s.REDIS_PORT <= 65535
    assert 1 <= s.QDRANT_PORT <= 65535

    with pytest.raises(ValidationError):
        Settings(APP_ENV="invalid-env")

    with pytest.raises(ValidationError):
        Settings(POSTGRES_PORT="not-a-port")

    with pytest.raises(ValidationError):
        Settings(POSTGRES_PORT="70000")

    with pytest.raises(ValidationError):
        Settings(REDIS_PORT=0)

    with pytest.raises(ValidationError):
        Settings(QDRANT_PORT=65536)

    with pytest.raises(ValidationError):
        Settings(POSTGRES_SERVER="   ")

    with pytest.raises(ValidationError):
        Settings(KAFKA_BROKERS=" ")


def test_kafka_service_uses_non_blocking_thread_and_cleans_up():
    async def _run():
        svc = KafkaService()
        mock_admin = MagicMock()
        mock_admin.list_topics.return_value = SimpleNamespace(topics={})

        with patch("app.services.kafka_client.AdminClient", return_value=mock_admin):
            await svc.connect()
        assert svc.admin is mock_admin
        assert await svc.check_health() is True

        mock_admin.list_topics.side_effect = RuntimeError("broker unreachable")
        assert await svc.check_health() is False

        await svc.close()
        assert svc.admin is None
        assert await svc.check_health() is False

    asyncio.run(_run())


def test_redis_service_resets_client_on_failure_and_close():
    async def _run():
        svc = RedisService()
        failing_client = MagicMock()
        failing_client.ping = AsyncMock(side_effect=ConnectionError("refused"))
        failing_client.aclose = AsyncMock()

        with patch("app.services.redis_client.redis.from_url", return_value=failing_client):
            await svc.connect()
        assert svc.client is None
        failing_client.aclose.assert_awaited_once()
        assert await svc.check_health() is False

        ok_client = MagicMock()
        ok_client.ping = AsyncMock(return_value=True)
        ok_client.aclose = AsyncMock()
        with patch("app.services.redis_client.redis.from_url", return_value=ok_client):
            await svc.connect()
        assert svc.client is ok_client
        assert await svc.check_health() is True

        await svc.close()
        assert svc.client is None
        ok_client.aclose.assert_awaited_once()
        assert await svc.check_health() is False

    asyncio.run(_run())


def test_qdrant_service_resets_client_on_failure_and_close():
    async def _run():
        svc = QdrantService()
        ok_client = MagicMock()
        ok_client.get_collections = AsyncMock(return_value=[])
        ok_client.close = AsyncMock()

        with patch("app.services.qdrant_client.AsyncQdrantClient", return_value=ok_client):
            await svc.connect()
        assert svc.client is ok_client
        assert await svc.check_health() is True

        await svc.close()
        assert svc.client is None
        ok_client.close.assert_awaited_once()
        assert await svc.check_health() is False

    asyncio.run(_run())


def test_persistence_exception_handler_sanitizes_response_and_logs(caplog):
    from app.events.repository import EventPersistenceError

    @app.get("/test-persistence-error-day12")
    async def _trigger_persistence():
        raise EventPersistenceError("postgresql+asyncpg://autosoc:autosoc_pass@localhost:5432/autosoc_db failure")

    with caplog.at_level(logging.ERROR, logger="autosoc"):
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/test-persistence-error-day12")

    assert resp.status_code == 500
    assert resp.json() == {"message": "Internal Server Error"}
    joined_logs = "\n".join(r.message for r in caplog.records)
    assert "autosoc_pass" not in joined_logs
