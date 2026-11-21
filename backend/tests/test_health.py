from fastapi.testclient import TestClient
from main import app
from unittest.mock import patch, AsyncMock
import pytest
from app.core.lifespan import lifespan

def test_health_check():
    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "autosoc-backend"

@patch("app.api.health.redis_service.check_health", return_value=True)
@patch("app.api.health.qdrant_service.check_health", return_value=True)
@patch("app.api.health.kafka_service.check_health", return_value=True)
@patch("app.api.health.check_db_health", return_value=True)
def test_readiness_healthy(mock_db, mock_kafka, mock_qdrant, mock_redis):
    with TestClient(app) as client:
        response = client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["postgres"] is True
        assert data["redis"] is True
        assert data["qdrant"] is True
        assert data["kafka"] is True

@patch("app.api.health.redis_service.check_health", return_value=True)
@patch("app.api.health.qdrant_service.check_health", return_value=True)
@patch("app.api.health.kafka_service.check_health", return_value=True)
@patch("app.api.health.check_db_health", return_value=False)
def test_readiness_postgres_fails(mock_db, mock_kafka, mock_qdrant, mock_redis):
    with TestClient(app) as client:
        response = client.get("/ready")
        assert response.status_code == 503
        data = response.json()
        detail = data["detail"]
        assert detail["status"] == "degraded"
        assert detail["postgres"] is False
        assert detail["redis"] is True
        assert detail["qdrant"] is True
        assert detail["kafka"] is True

@patch("app.api.health.redis_service.check_health", return_value=False)
@patch("app.api.health.qdrant_service.check_health", return_value=True)
@patch("app.api.health.kafka_service.check_health", return_value=True)
@patch("app.api.health.check_db_health", return_value=True)
def test_readiness_redis_fails(mock_db, mock_kafka, mock_qdrant, mock_redis):
    with TestClient(app) as client:
        response = client.get("/ready")
        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        assert detail["postgres"] is True
        assert detail["redis"] is False
        assert detail["qdrant"] is True
        assert detail["kafka"] is True

@patch("app.api.health.redis_service.check_health", return_value=True)
@patch("app.api.health.qdrant_service.check_health", return_value=False)
@patch("app.api.health.kafka_service.check_health", return_value=True)
@patch("app.api.health.check_db_health", return_value=True)
def test_readiness_qdrant_fails(mock_db, mock_kafka, mock_qdrant, mock_redis):
    with TestClient(app) as client:
        response = client.get("/ready")
        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        assert detail["postgres"] is True
        assert detail["redis"] is True
        assert detail["qdrant"] is False
        assert detail["kafka"] is True

@patch("app.api.health.redis_service.check_health", return_value=True)
@patch("app.api.health.qdrant_service.check_health", return_value=True)
@patch("app.api.health.kafka_service.check_health", return_value=False)
@patch("app.api.health.check_db_health", return_value=True)
def test_readiness_kafka_fails(mock_db, mock_kafka, mock_qdrant, mock_redis):
    with TestClient(app) as client:
        response = client.get("/ready")
        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        assert detail["postgres"] is True
        assert detail["redis"] is True
        assert detail["qdrant"] is True
        assert detail["kafka"] is False

@patch("app.api.health.redis_service.check_health", return_value=False)
@patch("app.api.health.qdrant_service.check_health", return_value=False)
@patch("app.api.health.kafka_service.check_health", return_value=False)
@patch("app.api.health.check_db_health", return_value=False)
def test_readiness_all_fail(mock_db, mock_kafka, mock_qdrant, mock_redis):
    with TestClient(app) as client:
        response = client.get("/ready")
        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["status"] == "degraded"
        assert detail["postgres"] is False
        assert detail["redis"] is False
        assert detail["qdrant"] is False
        assert detail["kafka"] is False

def test_lifespan_lifecycle():
    import asyncio
    async def run_check():
        with patch("app.core.lifespan.redis_service.connect", new_callable=AsyncMock) as m_r_c, \
             patch("app.core.lifespan.redis_service.close", new_callable=AsyncMock) as m_r_x, \
             patch("app.core.lifespan.qdrant_service.connect", new_callable=AsyncMock) as m_q_c, \
             patch("app.core.lifespan.qdrant_service.close", new_callable=AsyncMock) as m_q_x, \
             patch("app.core.lifespan.kafka_service.connect", new_callable=AsyncMock) as m_k_c, \
             patch("app.core.lifespan.kafka_service.close", new_callable=AsyncMock) as m_k_x:
            async with lifespan(app):
                m_r_c.assert_awaited_once()
                m_q_c.assert_awaited_once()
                m_k_c.assert_awaited_once()
            m_r_x.assert_awaited_once()
            m_q_x.assert_awaited_once()
            m_k_x.assert_awaited_once()

    asyncio.run(run_check())
