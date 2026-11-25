"""
AutoSOC API v1 - Security Event Ingestion and Retrieval Endpoints

Exposes minimal, contract-validated endpoints for accepting raw IngestionEnvelopes
into PostgreSQL and retrieving bounded recent ingestion summaries.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.events.api_schemas import (
    EventIngestionRequest,
    EventIngestionResponse,
    IngestedEventListResponse,
    IngestedEventSummary,
    build_payload_preview,
)
from app.events.repository import list_recent_envelopes, persist_raw_envelope
from app.events.schemas import SourceTypeEnum

router = APIRouter()


def _format_utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@router.post(
    "/ingest",
    status_code=status.HTTP_201_CREATED,
    response_model=EventIngestionResponse,
    summary="Ingest Raw Security Event Envelope",
)
async def ingest_event_envelope(
    envelope: EventIngestionRequest,
    db: AsyncSession = Depends(get_db),
) -> EventIngestionResponse:
    """
    Accept a raw security-event envelope conforming to the IngestionEnvelope contract,
    validate all required fields, and persist it unmodified in PostgreSQL.
    """
    record = await persist_raw_envelope(db, envelope)
    return EventIngestionResponse(
        ingestion_id=record.ingestion_id,
        source_type=SourceTypeEnum(record.source_type),
        status=record.processing_status,
        possible_duplicate=record.possible_duplicate,
        received_at=_format_utc_iso(record.received_at),
    )


@router.get(
    "/ingested",
    status_code=status.HTTP_200_OK,
    response_model=IngestedEventListResponse,
    summary="List Recently Ingested Event Envelopes",
)
async def get_recent_ingested_events(
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of recent ingested envelopes to return (1-100)",
    ),
    db: AsyncSession = Depends(get_db),
) -> IngestedEventListResponse:
    """
    Retrieve recently ingested raw event envelopes in deterministic descending order
    (`received_at DESC, id DESC`). Payloads are bounded to safe previews.
    """
    records = await list_recent_envelopes(db, limit=limit)
    items = [
        IngestedEventSummary(
            ingestion_id=rec.ingestion_id,
            source_type=SourceTypeEnum(rec.source_type),
            sensor_id=rec.sensor_id,
            ingest_time=rec.ingest_time,
            raw_hash=rec.raw_hash,
            payload_size_bytes=rec.payload_size_bytes,
            raw_payload_preview=build_payload_preview(rec.raw_payload),
            possible_duplicate=rec.possible_duplicate,
            status=rec.processing_status,
            received_at=_format_utc_iso(rec.received_at),
        )
        for rec in records
    ]
    return IngestedEventListResponse(items=items, count=len(items), limit=limit)
