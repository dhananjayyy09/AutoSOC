from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.redis_client import redis_service
from app.services.qdrant_client import qdrant_service
from app.services.kafka_client import kafka_service
from app.db.session import check_health as check_db_health
import logging

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

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint to verify backend status.
    """
    return {"status": "ok", "service": "autosoc-backend"}

@router.get("/ready", response_model=ReadinessResponse)
async def readiness_check():
    """
    Readiness check endpoint to verify infrastructure connectivity.
    """
    postgres_ok = await check_db_health()
    redis_ok = await redis_service.check_health()
    qdrant_ok = await qdrant_service.check_health()
    kafka_ok = await kafka_service.check_health()
    
    status = "ok" if (postgres_ok and redis_ok and qdrant_ok and kafka_ok) else "degraded"
    
    if status == "degraded":
        logger.warning(f"Readiness check degraded: Postgres={postgres_ok}, Redis={redis_ok}, Qdrant={qdrant_ok}, Kafka={kafka_ok}")
        raise HTTPException(
            status_code=503, 
            detail={
                "status": "degraded",
                "postgres": postgres_ok,
                "redis": redis_ok,
                "qdrant": qdrant_ok,
                "kafka": kafka_ok
            }
        )

    return {
        "status": status,
        "postgres": postgres_ok,
        "redis": redis_ok,
        "qdrant": qdrant_ok,
        "kafka": kafka_ok
    }
