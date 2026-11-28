import asyncio
from app.db.session import check_health, close_db
from app.services.redis_client import redis_service
from app.services.qdrant_client import qdrant_service
from app.services.kafka_client import kafka_service


async def main():
    try:
        await redis_service.connect()
        await qdrant_service.connect()
        await kafka_service.connect()

        print("Postgres:", await check_health())
        print("Redis:", await redis_service.check_health())
        print("Qdrant:", await qdrant_service.check_health())
        print("Kafka:", await kafka_service.check_health())
    finally:
        for closer in (
            redis_service.close,
            qdrant_service.close,
            kafka_service.close,
            close_db,
        ):
            try:
                await closer()
            except Exception:
                pass


if __name__ == "__main__":
    asyncio.run(main())
