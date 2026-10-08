from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.services.redis_client import redis_service
from app.services.qdrant_client import qdrant_service
from app.services.kafka_client import kafka_service
import logging

logger = logging.getLogger("autosoc")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up AutoSOC backend infrastructure...")
    await redis_service.connect()
    await qdrant_service.connect()
    await kafka_service.connect()
    
    yield
    
    logger.info("Shutting down AutoSOC backend infrastructure...")
    await redis_service.close()
    await qdrant_service.close()
    await kafka_service.close()
