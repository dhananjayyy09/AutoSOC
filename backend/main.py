from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.core.lifespan import lifespan
from app.core.logging import setup_logging
from app.core.exceptions import (
    global_exception_handler,
    validation_exception_handler,
    not_found_handler,
    duplicate_ingestion_handler,
    persistence_exception_handler,
    RequestLoggingMiddleware,
)
from app.events.repository import DuplicateIngestionIdError, EventPersistenceError
from app.api.health import router as health_router
from app.api.v1.router import api_v1_router


def create_app() -> FastAPI:
    # Initialise structured logging before the application starts
    setup_logging(log_level=settings.LOG_LEVEL)

    app = FastAPI(
        title=settings.PROJECT_NAME,
        description="Explainable Multi-Agent AI Platform for Autonomous Security Operations",
        version=settings.VERSION,
        lifespan=lifespan,
    )

    # ---- Middleware (outer-to-inner order) ----
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestLoggingMiddleware)

    # ---- Exception handlers ----
    app.add_exception_handler(Exception, global_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, not_found_handler)
    app.add_exception_handler(DuplicateIngestionIdError, duplicate_ingestion_handler)
    app.add_exception_handler(EventPersistenceError, persistence_exception_handler)

    # ---- Routers ----
    # Root health / readiness (consumed by frontend system status)
    app.include_router(health_router, tags=["Health"])

    # API v1
    app.include_router(api_v1_router, prefix=settings.API_V1_STR)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
