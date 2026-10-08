from fastapi.testclient import TestClient
from main import app
from app.core.config import settings

def test_config():
    assert settings.PROJECT_NAME == "AutoSOC API"
    assert settings.API_V1_STR == "/api/v1"
    assert "postgresql+asyncpg" in settings.async_database_uri

def test_404_handler():
    with TestClient(app) as client:
        response = client.get("/non-existent-route")
        assert response.status_code == 404
