import redis.asyncio as redis
from app.core.config import settings
import logging

logger = logging.getLogger("autosoc")

class RedisService:
    def __init__(self):
        self.client = None

    async def connect(self):
        client = redis.from_url(
            settings.redis_uri,
            decode_responses=True,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
        )
        try:
            await client.ping()
            self.client = client
            logger.info("Connected to Redis successfully.")
        except Exception as e:
            logger.error("Failed to connect to Redis (%s).", type(e).__name__)
            try:
                await client.aclose()
            except Exception:
                pass
            self.client = None

    async def close(self):
        if self.client:
            try:
                await self.client.aclose()
            finally:
                self.client = None

    async def check_health(self) -> bool:
        if not self.client:
            return False
        try:
            return await self.client.ping()
        except Exception:
            return False

redis_service = RedisService()
