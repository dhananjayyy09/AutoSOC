from qdrant_client import AsyncQdrantClient
from app.core.config import settings
import logging

logger = logging.getLogger("autosoc")

class QdrantService:
    def __init__(self):
        self.client = None

    async def connect(self):
        client = None
        try:
            client = AsyncQdrantClient(
                host=settings.QDRANT_HOST,
                port=settings.QDRANT_PORT,
                timeout=2.0,
            )
            # Check connection
            await client.get_collections()
            self.client = client
            logger.info("Connected to Qdrant successfully.")
        except Exception as e:
            logger.error("Failed to connect to Qdrant (%s).", type(e).__name__)
            if client is not None:
                try:
                    await client.close()
                except Exception:
                    pass
            self.client = None

    async def close(self):
        if self.client:
            try:
                await self.client.close()
            finally:
                self.client = None

    async def check_health(self) -> bool:
        if not self.client:
            return False
        try:
            await self.client.get_collections()
            return True
        except Exception:
            return False

qdrant_service = QdrantService()
