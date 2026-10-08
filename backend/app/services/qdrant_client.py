from qdrant_client import AsyncQdrantClient
from app.core.config import settings
import logging

logger = logging.getLogger("autosoc")

class QdrantService:
    def __init__(self):
        self.client = None

    async def connect(self):
        try:
            self.client = AsyncQdrantClient(host=settings.QDRANT_HOST, port=settings.QDRANT_PORT)
            # Check connection
            await self.client.get_collections()
            logger.info("Connected to Qdrant successfully.")
        except Exception as e:
            logger.error(f"Failed to connect to Qdrant: {e}")
            self.client = None

    async def close(self):
        if self.client:
            await self.client.close()

    async def check_health(self) -> bool:
        if not self.client:
            return False
        try:
            await self.client.get_collections()
            return True
        except Exception:
            return False

qdrant_service = QdrantService()
