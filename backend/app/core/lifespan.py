from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.services.redis_client import redis_service
from app.services.qdrant_client import qdrant_service
from app.services.kafka_client import kafka_service
from app.db.session import init_db, close_db
import logging

logger = logging.getLogger("autosoc")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up AutoSOC backend infrastructure...")
    
    # 1. PostgreSQL
    db_ok = await init_db()
    if not db_ok:
        logger.warning("PostgreSQL startup check degraded: database connection failed.")

    # 2. Redis
    await redis_service.connect()
    if not await redis_service.check_health():
        logger.warning("Redis startup check degraded: cache service connection failed.")

    # 3. Qdrant
    await qdrant_service.connect()
    if not await qdrant_service.check_health():
        logger.warning("Qdrant startup check degraded: vector store connection failed.")

    # 4. Kafka
    await kafka_service.connect()
    if not await kafka_service.check_health():
        logger.warning("Kafka startup check degraded: broker connection failed.")

    logger.info("AutoSOC backend startup completed.")
    
    yield

    logger.info("Shutting down AutoSOC backend infrastructure...")
    for service_name, closer in (
        ("redis", redis_service.close),
        ("qdrant", qdrant_service.close),
        ("kafka", kafka_service.close),
        ("postgres", close_db),
    ):
        try:
            await closer()
        except Exception as exc:
            logger.warning(
                "Error shutting down %s infrastructure client (%s).",
                service_name,
                type(exc).__name__,
            )
    logger.info("AutoSOC backend shutdown completed.")
