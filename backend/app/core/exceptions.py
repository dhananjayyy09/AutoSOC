import logging
import time
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("autosoc")


# ---------------------------------------------------------------------------
# Global unhandled-exception handler (500)
# ---------------------------------------------------------------------------

async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a sanitised 500 response — no internal trace exposed to the caller."""
    logger.error("Unhandled Exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal Server Error"},
    )


# ---------------------------------------------------------------------------
# 422 Validation error handler
# ---------------------------------------------------------------------------

async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Replace FastAPI's default verbose Pydantic 422 response with a consistent
    structure that matches the rest of the API's error format.
    """
    errors = []
    for err in exc.errors():
        errors.append(
            {
                "field": " -> ".join(str(loc) for loc in err.get("loc", [])),
                "message": err.get("msg", ""),
                "type": err.get("type", ""),
            }
        )
    logger.warning(
        "Request validation failed on %s %s: %s",
        request.method,
        request.url.path,
        errors,
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"message": "Validation error", "errors": errors},
    )


# ---------------------------------------------------------------------------
# 404 Not-found handler
# ---------------------------------------------------------------------------

async def not_found_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Return a consistent 404 response body.
    Only handles genuine 404 Not Found status; all other HTTP exceptions
    (e.g. 503 from the readiness endpoint) pass through normally.
    """
    from starlette.exceptions import HTTPException as StarletteHTTPException
    if isinstance(exc, StarletteHTTPException) and exc.status_code != 404:
        # Let FastAPI/Starlette handle non-404 HTTP exceptions normally
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"message": "Not found"},
    )


# ---------------------------------------------------------------------------
# Event ingestion domain error handlers (409 / 500)
# ---------------------------------------------------------------------------

async def duplicate_ingestion_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a consistent 409 Conflict when an ingestion_id is submitted twice."""
    logger.warning("Duplicate ingestion_id conflict on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"message": "Duplicate ingestion_id: event envelope already exists"},
    )


async def persistence_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a sanitised 500 response on storage failures without exposing DB details or credentials."""
    logger.error(
        "Persistence error on %s %s (%s)",
        request.method,
        request.url.path,
        type(exc).__name__,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"message": "Internal Server Error"},
    )


# ---------------------------------------------------------------------------
# Request / response logging middleware
# ---------------------------------------------------------------------------

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Log each HTTP request: method, path, status code, and duration.

    Sensitive headers (Authorization, Cookie, X-API-Key) and request bodies
    are intentionally NOT logged to avoid credential exposure.
    """

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000
        logger.info(
            "HTTP %s %s -> %d (%.1fms)",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        return response
