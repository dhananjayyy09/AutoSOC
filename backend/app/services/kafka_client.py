from confluent_kafka.admin import AdminClient
from app.core.config import settings
import logging

logger = logging.getLogger("autosoc")

class KafkaService:
    def __init__(self):
        self.admin = None

    async def connect(self):
        try:
            # Minimal connection check using AdminClient
            self.admin = AdminClient({
                'bootstrap.servers': settings.KAFKA_BROKERS
            })
            metadata = self.admin.list_topics(timeout=3.0)
            logger.info("Connected to Kafka successfully.")
        except Exception as e:
            logger.error(f"Failed to connect to Kafka: {e}")
            self.admin = None

    async def close(self):
        self.admin = None
        
    async def check_health(self) -> bool:
        if self.admin is None:
            return False
        try:
            # list_topics is synchronous in confluent_kafka, so we wrap it lightly
            # In a real async scenario, we might use aiokafka or run in executor
            self.admin.list_topics(timeout=2.0)
            return True
        except Exception:
            return False

kafka_service = KafkaService()
