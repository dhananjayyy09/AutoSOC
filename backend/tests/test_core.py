from fastapi.testclient import TestClient
from main import app
from app.core.config import settings

def test_config():
    assert settings.PROJECT_NAME == "AutoSOC API"
    assert settings.API_V1_STR == "/api/v1"
    assert "postgresql+asyncpg" in settings.async_database_uri
    assert settings.APP_ENV in ("development", "production", "testing")

def test_404_handler():
    with TestClient(app) as client:
        response = client.get("/non-existent-route")
        assert response.status_code == 404

def test_global_exception_handler():
    # Register a temporary test route that triggers an unhandled Exception
    @app.get("/test-unhandled-exception")
    async def trigger_exception():
        raise RuntimeError("Test unhandled server exception")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/test-unhandled-exception")
        assert response.status_code == 500
        assert response.json() == {"message": "Internal Server Error"}

def test_v1_system_info():
    with TestClient(app) as client:
        response = client.get("/api/v1/system/info")
        assert response.status_code == 200
        data = response.json()
        assert data["project_name"] == settings.PROJECT_NAME
        assert data["version"] == settings.VERSION
        assert data["api_version"] == "v1"
        assert data["environment"] == settings.APP_ENV
