from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import text
from app.core.config import settings
from app.db.base import Base
import logging

logger = logging.getLogger("autosoc")

engine = create_async_engine(settings.async_database_uri, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async database session and guarantees closure."""
    async with AsyncSessionLocal() as session:
        yield session

async def check_health() -> bool:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

async def init_db() -> bool:
    try:
        # Ensure ORM models are imported and registered before metadata sync
        import app.events.models  # noqa: F401
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Connected to PostgreSQL and verified schema successfully.")
        return True
    except Exception as e:
        logger.error("Failed to connect to PostgreSQL (%s).", type(e).__name__)
        return False

async def close_db():
    logger.info("Disposing PostgreSQL engine connections.")
    await engine.dispose()
