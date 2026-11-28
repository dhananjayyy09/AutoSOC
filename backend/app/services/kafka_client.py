import asyncio
from confluent_kafka.admin import AdminClient
from app.core.config import settings
import logging

logger = logging.getLogger("autosoc")

class KafkaService:
    def __init__(self):
        self.admin = None

    async def connect(self):
        try:
            # Minimal connection check using AdminClient off the asyncio event loop
            admin = AdminClient({
                'bootstrap.servers': settings.KAFKA_BROKERS
            })
            await asyncio.to_thread(admin.list_topics, timeout=3.0)
            self.admin = admin
            logger.info("Connected to Kafka successfully.")
        except Exception as e:
            logger.error("Failed to connect to Kafka (%s).", type(e).__name__)
            self.admin = None

    async def close(self):
        self.admin = None

    async def check_health(self) -> bool:
        if self.admin is None:
            return False
        try:
            await asyncio.to_thread(self.admin.list_topics, timeout=2.0)
            return True
        except Exception:
            return False

kafka_service = KafkaService()
