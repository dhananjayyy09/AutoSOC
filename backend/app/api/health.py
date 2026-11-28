import asyncio
import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.db.session import check_health as check_db_health
from app.services.kafka_client import kafka_service
from app.services.qdrant_client import qdrant_service
from app.services.redis_client import redis_service

logger = logging.getLogger("autosoc")

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    service: str


class ReadinessResponse(BaseModel):
    status: str
    postgres: bool
    redis: bool
    qdrant: bool
    kafka: bool


def _coerce_probe_result(service_name: str, result: object) -> bool:
    if isinstance(result, BaseException):
        logger.warning(
            "Readiness probe failed for %s (%s)",
            service_name,
            type(result).__name__,
        )
        return False
    return bool(result)


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint to verify backend status.
    """
    return {"status": "ok", "service": "autosoc-backend"}


@router.get("/ready", response_model=ReadinessResponse)
async def readiness_check():
    """
    Readiness check endpoint to verify infrastructure connectivity concurrently.
    """
    raw_results = await asyncio.gather(
        check_db_health(),
        redis_service.check_health(),
        qdrant_service.check_health(),
        kafka_service.check_health(),
        return_exceptions=True,
    )
    postgres_ok, redis_ok, qdrant_ok, kafka_ok = (
        _coerce_probe_result(name, res)
        for name, res in zip(("postgres", "redis", "qdrant", "kafka"), raw_results)
    )

    status = "ok" if (postgres_ok and redis_ok and qdrant_ok and kafka_ok) else "degraded"

    if status == "degraded":
        logger.warning(
            "Readiness check degraded: Postgres=%s, Redis=%s, Qdrant=%s, Kafka=%s",
            postgres_ok,
            redis_ok,
            qdrant_ok,
            kafka_ok,
        )
        raise HTTPException(
            status_code=503,
            detail={
                "status": "degraded",
                "postgres": postgres_ok,
                "redis": redis_ok,
                "qdrant": qdrant_ok,
                "kafka": kafka_ok,
            },
        )

    return {
        "status": status,
        "postgres": postgres_ok,
        "redis": redis_ok,
        "qdrant": qdrant_ok,
        "kafka": kafka_ok,
    }
