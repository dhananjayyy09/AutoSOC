"""
AutoSOC - Asynchronous Security Event Ingestion Repository

Handles PostgreSQL persistence and bounded retrieval of raw IngestionEnvelopes
via SQLAlchemy async sessions. Ensures explicit transaction rollback on error,
enforces delivery-attempt uniqueness (ingestion_id), and flags duplicate raw
payloads (raw_hash) without silently discarding events.
"""

import logging
from typing import List

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.events.models import RawEventEnvelope
from app.events.schemas import IngestionEnvelope

logger = logging.getLogger("autosoc")


class DuplicateIngestionIdError(Exception):
    """Raised when an envelope shares an ingestion_id with an already-persisted delivery."""

    def __init__(self, ingestion_id: str) -> None:
        self.ingestion_id = ingestion_id
        super().__init__(f"Duplicate ingestion_id: {ingestion_id}")


class EventPersistenceError(Exception):
    """Raised when persisting or reading security events from PostgreSQL fails."""


async def persist_raw_envelope(
    session: AsyncSession, envelope: IngestionEnvelope
) -> RawEventEnvelope:
    """
    Persist a validated IngestionEnvelope to PostgreSQL.

    - Preserves `raw_payload` verbatim.
    - Rejects duplicate `ingestion_id` (unique delivery attempt per contract §2.4).
    - Flags duplicate `raw_hash` (different `ingestion_id`) with
      `possible_duplicate=True` and stores it rather than discarding (§7.4).
    - Rolls back and raises EventPersistenceError on database failure.
    """
    try:
        # 1. Enforce delivery-attempt uniqueness on ingestion_id
        existing_id = await session.scalar(
            select(RawEventEnvelope.id)
            .where(RawEventEnvelope.ingestion_id == envelope.ingestion_id)
            .limit(1)
        )
        if existing_id is not None:
            raise DuplicateIngestionIdError(envelope.ingestion_id)

        # 2. Check for byte-identical raw_hash already persisted (flag only, never discard)
        existing_hash_id = await session.scalar(
            select(RawEventEnvelope.id)
            .where(RawEventEnvelope.raw_hash == envelope.raw_hash)
            .limit(1)
        )
        is_possible_duplicate = existing_hash_id is not None

        payload_bytes = len(envelope.raw_payload.encode("utf-8"))
        source_value = (
            envelope.source_type.value
            if hasattr(envelope.source_type, "value")
            else str(envelope.source_type)
        )

        record = RawEventEnvelope(
            ingestion_id=envelope.ingestion_id,
            source_type=source_value,
            sensor_id=envelope.sensor_id,
            ingest_time=envelope.ingest_time,
            raw_hash=envelope.raw_hash,
            raw_payload=envelope.raw_payload,
            payload_size_bytes=payload_bytes,
            possible_duplicate=is_possible_duplicate,
            processing_status="accepted",
        )

        session.add(record)
        await session.commit()
        await session.refresh(record)

        logger.info(
            "Persisted raw event envelope ingestion_id=%s source_type=%s possible_duplicate=%s size=%dB",
            record.ingestion_id,
            record.source_type,
            record.possible_duplicate,
            record.payload_size_bytes,
        )
        return record

    except DuplicateIngestionIdError:
        await session.rollback()
        raise
    except IntegrityError as exc:
        await session.rollback()
        # Handle concurrent duplicate ingestion_id race condition safely
        logger.warning(
            "IntegrityError persisting ingestion_id=%s (likely concurrent duplicate): %s",
            envelope.ingestion_id,
            type(exc).__name__,
        )
        raise DuplicateIngestionIdError(envelope.ingestion_id) from exc
    except SQLAlchemyError as exc:
        await session.rollback()
        logger.error(
            "Database failure persisting event envelope ingestion_id=%s: %s",
            envelope.ingestion_id,
            exc,
            exc_info=True,
        )
        raise EventPersistenceError("Database persistence failure") from exc


async def list_recent_envelopes(
    session: AsyncSession, limit: int = 20
) -> List[RawEventEnvelope]:
    """
    Retrieve recently ingested raw event envelopes using deterministic descending order
    (`received_at DESC, id DESC`).
    """
    try:
        stmt = (
            select(RawEventEnvelope)
            .order_by(RawEventEnvelope.received_at.desc(), RawEventEnvelope.id.desc())
            .limit(limit)
        )
        result = await session.scalars(stmt)
        return list(result.all())
    except SQLAlchemyError as exc:
        logger.error("Database failure retrieving recent event envelopes: %s", exc, exc_info=True)
        raise EventPersistenceError("Database retrieval failure") from exc
