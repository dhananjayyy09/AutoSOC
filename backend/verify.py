import asyncio
from app.db.session import check_health
from app.services.redis_client import redis_service
from app.services.qdrant_client import qdrant_service
from app.services.kafka_client import kafka_service

async def main():
    await redis_service.connect()
    await qdrant_service.connect()
    await kafka_service.connect()

    print('Postgres:', await check_health())
    print('Redis:', await redis_service.check_health())
    print('Qdrant:', await qdrant_service.check_health())
    print('Kafka:', await kafka_service.check_health())
    
    await redis_service.close()
    await qdrant_service.close()
    await kafka_service.close()

asyncio.run(main())
