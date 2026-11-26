"""
AutoSOC - Asynchronous Security Event Ingestion Repository

Handles PostgreSQL persistence and bounded retrieval of raw IngestionEnvelopes
via SQLAlchemy async sessions. Ensures explicit transaction rollback on error,
enforces delivery-attempt uniqueness (ingestion_id), and flags duplicate raw
payloads (raw_hash) without silently discarding events.
"""

import inspect
import logging
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.events.enrichment_contract import EnrichmentStatusEnum
from app.events.models import EventEnrichment, NormalizedEvent, RawEventEnvelope
from app.events.query_contract import (
    NormalizedEventQueryParams,
    NormalizedEventSortField,
    SEARCHABLE_NORMALIZED_EVENT_FIELDS,
    SORT_FIELD_TO_ORM_COLUMN,
    SortOrderEnum,
    escape_like_pattern,
)
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
    session: AsyncSession,
    envelope: IngestionEnvelope,
    processing_status: str = "accepted",
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
            processing_status=processing_status,
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


async def get_raw_envelope_by_ingestion_id(
    session: AsyncSession, ingestion_id: str
) -> Optional[RawEventEnvelope]:
    """Retrieve a persisted RawEventEnvelope by its ingestion_id."""
    try:
        return await session.scalar(
            select(RawEventEnvelope)
            .where(RawEventEnvelope.ingestion_id == ingestion_id)
            .limit(1)
        )
    except SQLAlchemyError as exc:
        logger.error(
            "Database failure retrieving raw envelope ingestion_id=%s: %s",
            ingestion_id,
            exc,
            exc_info=True,
        )
        raise EventPersistenceError("Database retrieval failure") from exc


async def get_normalized_event_by_ingestion_id(
    session: AsyncSession, ingestion_id: str
) -> Optional[NormalizedEvent]:
    """Retrieve a NormalizedEvent by its originating ingestion_id."""
    try:
        return await session.scalar(
            select(NormalizedEvent)
            .where(NormalizedEvent.ingestion_id == ingestion_id)
            .limit(1)
        )
    except SQLAlchemyError as exc:
        logger.error(
            "Database failure retrieving normalized event for ingestion_id=%s: %s",
            ingestion_id,
            exc,
            exc_info=True,
        )
        raise EventPersistenceError("Database retrieval failure") from exc


async def get_normalized_event_by_event_id(
    session: AsyncSession, event_id: str
) -> Optional[NormalizedEvent]:
    """Retrieve a single NormalizedEvent by its stable event_id."""
    try:
        return await session.scalar(
            select(NormalizedEvent)
            .where(NormalizedEvent.event_id == event_id)
            .limit(1)
        )
    except SQLAlchemyError as exc:
        logger.error(
            "Database failure retrieving normalized event event_id=%s: %s",
            event_id,
            exc,
            exc_info=True,
        )
        raise EventPersistenceError("Database retrieval failure") from exc


async def persist_normalized_event(
    session: AsyncSession, record: NormalizedEvent
) -> NormalizedEvent:
    """
    Persist a NormalizedEvent (success or failure record) in PostgreSQL.
    Rolls back and raises EventPersistenceError on database failure.
    """
    try:
        session.add(record)
        await session.commit()
        await session.refresh(record)
        logger.info(
            "Persisted normalized event ingestion_id=%s event_id=%s status=%s",
            record.ingestion_id,
            record.event_id,
            record.normalization_status,
        )
        return record
    except SQLAlchemyError as exc:
        await session.rollback()
        logger.error(
            "Database failure persisting normalized event for ingestion_id=%s: %s",
            record.ingestion_id,
            exc,
            exc_info=True,
        )
        raise EventPersistenceError("Normalized event persistence failure") from exc


_SEARCHABLE_NORMALIZED_COLUMNS = tuple(
    getattr(NormalizedEvent, field_name)
    for field_name in SEARCHABLE_NORMALIZED_EVENT_FIELDS
)

_SORT_COLUMN_MAP = {
    sort_field: getattr(NormalizedEvent, col_name)
    for sort_field, col_name in SORT_FIELD_TO_ORM_COLUMN.items()
}


def _build_normalized_event_filters(params: NormalizedEventQueryParams) -> List[Any]:
    filters: List[Any] = []
    if params.source_type is not None:
        filters.append(NormalizedEvent.source_type == params.source_type.value)
    if params.normalization_status is not None:
        filters.append(
            NormalizedEvent.normalization_status == params.normalization_status.value
        )
    if params.event_category is not None:
        filters.append(NormalizedEvent.event_category == params.event_category.value)
    if params.event_type is not None:
        filters.append(NormalizedEvent.event_type == params.event_type)
    if params.severity is not None:
        filters.append(NormalizedEvent.severity == params.severity)
    if params.start_time is not None:
        filters.append(NormalizedEvent.event_timestamp >= params.start_time)
    if params.end_time is not None:
        filters.append(NormalizedEvent.event_timestamp <= params.end_time)
    if params.search is not None:
        pattern = f"%{escape_like_pattern(params.search)}%"
        filters.append(
            or_(*(col.ilike(pattern, escape="\\") for col in _SEARCHABLE_NORMALIZED_COLUMNS))
        )
    return filters


def _resolve_sort_clauses(
    sort_by: NormalizedEventSortField, sort_order: SortOrderEnum
) -> Tuple[Any, ...]:
    primary_col = _SORT_COLUMN_MAP[sort_by]
    if sort_order == SortOrderEnum.ASC:
        return (primary_col.asc().nulls_last(), NormalizedEvent.id.asc())
    return (primary_col.desc().nulls_last(), NormalizedEvent.id.desc())


async def query_normalized_events(
    session: AsyncSession, params: NormalizedEventQueryParams
) -> Tuple[List[NormalizedEvent], int]:
    """
    Query normalized events at the database level with filtering, search,
    deterministic sorting, and offset pagination. Returns `(items, total)`.
    """
    filters = _build_normalized_event_filters(params)
    order_clauses = _resolve_sort_clauses(params.sort_by, params.sort_order)

    try:
        count_stmt = select(func.count(NormalizedEvent.id))
        data_stmt = select(NormalizedEvent)
        if filters:
            count_stmt = count_stmt.where(*filters)
            data_stmt = data_stmt.where(*filters)

        total_raw = await session.scalar(count_stmt)
        data_stmt = (
            data_stmt.order_by(*order_clauses)
            .limit(params.limit)
            .offset(params.offset)
        )
        result = await session.scalars(data_stmt)
        items = list(result.all())
        total = int(total_raw) if total_raw is not None else len(items)
        return items, total
    except SQLAlchemyError as exc:
        logger.error("Database failure querying normalized events: %s", exc, exc_info=True)
        raise EventPersistenceError("Database retrieval failure") from exc


async def list_recent_normalized_events(
    session: AsyncSession, limit: int = 20
) -> List[NormalizedEvent]:
    """
    Retrieve recently processed normalized events using deterministic descending order
    (`created_at DESC, id DESC`).
    """
    items, _ = await query_normalized_events(
        session, NormalizedEventQueryParams(limit=limit)
    )
    return items


async def get_event_enrichment_by_event_id(
    session: AsyncSession, event_id: str
) -> Optional[EventEnrichment]:
    """Retrieve an EventEnrichment record by its linked normalized event_id."""
    try:
        return await session.scalar(
            select(EventEnrichment)
            .where(EventEnrichment.event_id == event_id)
            .limit(1)
        )
    except SQLAlchemyError as exc:
        logger.error(
            "Database failure retrieving enrichment for event_id=%s: %s",
            event_id,
            exc,
            exc_info=True,
        )
        raise EventPersistenceError("Database retrieval failure") from exc


async def get_event_enrichments_by_event_ids(
    session: AsyncSession, event_ids: List[str]
) -> Dict[str, EventEnrichment]:
    """
    Batch-retrieve EventEnrichment records keyed by normalized event_id in one
    database query (eliminates N+1 lookups during paginated normalized queries).
    """
    clean_ids = list(dict.fromkeys(eid for eid in event_ids if isinstance(eid, str) and eid))
    if not clean_ids:
        return {}
    try:
        result = await session.scalars(
            select(EventEnrichment).where(EventEnrichment.event_id.in_(clean_ids))
        )
        rows = result.all() if result is not None else []
        if inspect.iscoroutine(rows):
            rows.close()
            return {}
        if not isinstance(rows, (list, tuple)):
            return {}
        out: Dict[str, EventEnrichment] = {}
        for row in rows:
            if isinstance(row, EventEnrichment) and row.event_id:
                out[row.event_id] = row
        return out
    except SQLAlchemyError as exc:
        logger.error(
            "Database failure batch-retrieving enrichments for %d events: %s",
            len(clean_ids),
            exc,
            exc_info=True,
        )
        raise EventPersistenceError("Database retrieval failure") from exc


async def persist_or_update_event_enrichment(
    session: AsyncSession, record: EventEnrichment
) -> EventEnrichment:
    """
    Insert or update an EventEnrichment record without modifying normalized_events
    or raw_event_envelopes. Rolls back on SQLAlchemy error.
    """
    try:
        session.add(record)
        await session.commit()
        await session.refresh(record)
        logger.info(
            "Persisted event enrichment enrichment_id=%s event_id=%s status=%s attempt=%s",
            record.enrichment_id,
            record.event_id,
            record.enrichment_status,
            record.attempt_count,
        )
        return record
    except SQLAlchemyError as exc:
        await session.rollback()
        logger.error(
            "Database failure persisting event enrichment for event_id=%s: %s",
            record.event_id,
            exc,
            exc_info=True,
        )
        raise EventPersistenceError("Event enrichment persistence failure") from exc


async def query_event_enrichments(
    session: AsyncSession,
    *,
    limit: int = 20,
    offset: int = 0,
    enrichment_status: Optional[EnrichmentStatusEnum] = None,
    provider: Optional[str] = None,
    sort_order: SortOrderEnum = SortOrderEnum.DESC,
) -> Tuple[List[EventEnrichment], int]:
    """
    Query persisted enrichment records at the database level with deterministic
    ordering (`created_at`, `id` tie-breaker) and offset pagination.
    """
    filters: List[Any] = []
    if enrichment_status is not None:
        filters.append(EventEnrichment.enrichment_status == enrichment_status.value)
    if provider is not None:
        filters.append(EventEnrichment.provider == provider)

    order_clauses = (
        (EventEnrichment.created_at.asc(), EventEnrichment.id.asc())
        if sort_order == SortOrderEnum.ASC
        else (EventEnrichment.created_at.desc(), EventEnrichment.id.desc())
    )

    try:
        count_stmt = select(func.count(EventEnrichment.id))
        data_stmt = select(EventEnrichment)
        if filters:
            count_stmt = count_stmt.where(*filters)
            data_stmt = data_stmt.where(*filters)

        total_raw = await session.scalar(count_stmt)
        data_stmt = data_stmt.order_by(*order_clauses).limit(limit).offset(offset)
        result = await session.scalars(data_stmt)
        items = list(result.all())
        total = int(total_raw) if total_raw is not None else len(items)
        return items, total
    except SQLAlchemyError as exc:
        logger.error(
            "Database failure querying event enrichments: %s",
            exc,
            exc_info=True,
        )
        raise EventPersistenceError("Database retrieval failure") from exc
