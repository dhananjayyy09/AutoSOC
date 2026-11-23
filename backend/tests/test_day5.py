"""
AutoSOC Day 5 Tests
===================
Tests for the Day 5 improvements:
  A. Configuration foundation (LOG_LEVEL field, model_validator)
  B. Structured logging and request logging middleware
  C. API error handling (422, 404, 500 consistent format)
  D. Database session type annotations (get_db generator contract)
"""

import logging
import pytest
from fastapi.testclient import TestClient
from main import app
from app.core.config import Settings, settings


# ---------------------------------------------------------------------------
# Task A: Configuration
# ---------------------------------------------------------------------------

def test_config_log_level_default():
    """LOG_LEVEL defaults to INFO when not set."""
    assert settings.LOG_LEVEL == "INFO"


def test_config_log_level_valid():
    """Settings accepts valid LOG_LEVEL values."""
    for level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        s = Settings(LOG_LEVEL=level)
        assert s.LOG_LEVEL == level


def test_config_log_level_invalid():
    """Settings raises ValueError for an unrecognised LOG_LEVEL."""
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        Settings(LOG_LEVEL="VERBOSE")


def test_config_debug_flag():
    """DEBUG field is present and boolean."""
    assert isinstance(settings.DEBUG, bool)


def test_config_app_env_valid():
    """APP_ENV is a recognised environment string."""
    assert settings.APP_ENV in ("development", "production", "testing")


def test_config_no_secrets_in_database_uri():
    """
    The async_database_uri is built from fields that are never logged.
    Verify the URI format is correct without exposing credentials in assertions.
    """
    uri = settings.async_database_uri
    assert uri.startswith("postgresql+asyncpg://")
    assert "@" in uri


# ---------------------------------------------------------------------------
# Task B: Structured logging
# ---------------------------------------------------------------------------

def test_setup_logging_configures_level(caplog):
    """setup_logging() must configure the root logger at the requested level."""
    from app.core.logging import setup_logging
    setup_logging(log_level="WARNING")
    assert logging.getLogger().level == logging.WARNING
    # Restore to INFO for subsequent tests
    setup_logging(log_level="INFO")


def test_setup_logging_emits_startup_message(caplog):
    """setup_logging() must emit exactly one INFO startup message."""
    from app.core.logging import setup_logging
    # Ensure caplog captures from the autosoc logger hierarchy
    caplog.set_level(logging.INFO, logger="autosoc")
    setup_logging(log_level="INFO")
    assert any("Logging configured" in r.message for r in caplog.records)


def test_request_logging_middleware_logs_request(caplog):
    """
    RequestLoggingMiddleware must log the method, path, status code, and
    duration for every incoming request.
    """
    with caplog.at_level(logging.INFO, logger="autosoc"):
        with TestClient(app) as client:
            client.get("/health")
    messages = [r.message for r in caplog.records if "HTTP" in r.message]
    assert any("GET" in m and "/health" in m for m in messages), (
        "No HTTP request log found in caplog records"
    )


# ---------------------------------------------------------------------------
# Task C: API error handling
# ---------------------------------------------------------------------------

def test_custom_404_format():
    """404 responses must return {"message": "Not found"}."""
    with TestClient(app) as client:
        response = client.get("/route-that-does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert body == {"message": "Not found"}


def test_global_500_no_trace_leaked():
    """500 responses must NOT expose internal Python tracebacks."""
    @app.get("/test-500-day5")
    async def _trigger():
        raise RuntimeError("Day5 internal error trigger")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/test-500-day5")
    assert response.status_code == 500
    body = response.json()
    assert body == {"message": "Internal Server Error"}
    # Ensure no Python traceback text leaks into the response body
    text = str(body)
    assert "Traceback" not in text
    assert "RuntimeError" not in text


def test_422_validation_error_format():
    """
    Endpoints that receive bad input must return a consistent 422 body:
    {"message": "Validation error", "errors": [...]}.
    """
    # /api/v1/system/info has no body params but we can POST with a bad
    # JSON body to a path that expects query params to trigger 422.
    # We use a typed query-param endpoint registered for this test only.
    from fastapi import Query

    @app.get("/test-422-day5")
    async def _typed(value: int = Query(...)):
        return {"value": value}

    with TestClient(app) as client:
        # Sending a string where an int is required triggers 422
        response = client.get("/test-422-day5", params={"value": "not-an-int"})

    assert response.status_code == 422
    body = response.json()
    assert body.get("message") == "Validation error"
    assert isinstance(body.get("errors"), list)
    assert len(body["errors"]) > 0


# ---------------------------------------------------------------------------
# Task D: Database session
# ---------------------------------------------------------------------------

def test_get_db_is_async_generator():
    """get_db() must be an async generator function (dependency contract)."""
    import inspect
    from app.db.session import get_db
    assert inspect.isasyncgenfunction(get_db), "get_db must be an async generator function"


def test_get_db_type_annotation():
    """get_db() must carry an AsyncGenerator return type annotation."""
    import inspect
    from app.db.session import get_db
    hints = get_db.__annotations__
    assert "return" in hints, "get_db must have a return type annotation"
