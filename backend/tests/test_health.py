from fastapi.testclient import TestClient
from main import app

from unittest.mock import patch

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
