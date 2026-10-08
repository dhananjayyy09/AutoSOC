import redis.asyncio as redis
from app.core.config import settings
import logging

logger = logging.getLogger("autosoc")

class RedisService:
    def __init__(self):
        self.client = None

    async def connect(self):
        self.client = redis.from_url(settings.redis_uri, decode_responses=True)
        try:
            await self.client.ping()
            logger.info("Connected to Redis successfully.")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")

    async def close(self):
        if self.client:
            await self.client.aclose()

    async def check_health(self) -> bool:
        if not self.client:
            return False
        try:
            return await self.client.ping()
        except Exception:
            return False

redis_service = RedisService()
