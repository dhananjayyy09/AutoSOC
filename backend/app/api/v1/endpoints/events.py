"""
AutoSOC API v1 - Security Event Ingestion, Normalization, and Retrieval Endpoints

Exposes endpoints for:
  - Accepting raw IngestionEnvelopes into PostgreSQL and triggering post-persist
    deterministic normalization (`POST /api/v1/events/ingest`)
  - Retrieving bounded recent raw ingestion summaries (`GET /api/v1/events/ingested`)
  - Retrieving bounded normalized security events (`GET /api/v1/events/normalized`,
    `GET /api/v1/events/normalized/{event_id}`)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.events.api_schemas import (
    EventIngestionResponse,
    IngestedEventListResponse,
    IngestedEventSummary,
    NormalizedEventListResponse,
    NormalizedEventResponse,
    build_payload_preview,
)
from app.events.models import NormalizedEvent
from app.events.normalization_service import NormalizationService
from app.events.repository import (
    get_normalized_event_by_event_id,
    list_recent_envelopes,
    list_recent_normalized_events,
    persist_raw_envelope,
)
from app.events.schemas import IngestionEnvelope, SourceTypeEnum
from app.events.validation import (
    MAX_RAW_PAYLOAD_BYTES,
    ValidationErrorCategory,
    validate_ingestion_envelope,
)

logger = logging.getLogger("autosoc")

router = APIRouter()
_default_normalization_service = NormalizationService()


def _format_utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _to_normalized_response(rec: NormalizedEvent) -> NormalizedEventResponse:
    return NormalizedEventResponse(
        event_id=rec.event_id,
        ingestion_id=rec.ingestion_id,
        raw_envelope_id=rec.raw_envelope_id,
        timestamp=rec.event_timestamp,
        source_type=SourceTypeEnum(rec.source_type),
        sensor_id=rec.sensor_id,
        event_category=rec.event_category,
        event_type=rec.event_type,
        host=rec.host,
        user=rec.user_name,
        source_ip=rec.source_ip,
        destination_ip=rec.destination_ip,
        source_port=rec.source_port,
        destination_port=rec.destination_port,
        protocol=rec.protocol,
        process=rec.process,
        file_hash=rec.file_hash,
        domain=rec.domain,
        command_line=rec.command_line,
        severity=rec.severity,
        metadata=rec.event_metadata or {},
        normalization_status=rec.normalization_status,
        normalization_errors=list(rec.normalization_errors or []),
        normalization_warnings=list(rec.normalization_warnings or []),
        created_at=_format_utc_iso(rec.created_at),
    )


@router.post(
    "/ingest",
    status_code=status.HTTP_201_CREATED,
    response_model=EventIngestionResponse,
    summary="Ingest Raw Security Event Envelope",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": IngestionEnvelope.model_json_schema()
                }
            },
        }
    },
)
async def ingest_event_envelope(
    payload: Dict[str, Any] = Body(...),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Accept a raw security-event envelope conforming to the IngestionEnvelope contract,
    validate it, persist it unmodified in PostgreSQL, and then run deterministic
    normalization without risking raw source evidence on normalization failure.
    """
    validation_result = validate_ingestion_envelope(payload)

    if not validation_result.valid or validation_result.envelope is None:
        errors = [
            {
                "field": (
                    issue.field
                    if issue.field.startswith("body")
                    else f"body -> {issue.field}"
                ),
                "message": issue.message,
                "type": issue.category.value,
            }
            for issue in validation_result.errors
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"message": "Validation error", "errors": errors},
        )

    if validation_result.raw_truncated:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "message": "Validation error",
                "errors": [
                    {
                        "field": "body -> raw_payload",
                        "message": f"raw_payload exceeds maximum size of {MAX_RAW_PAYLOAD_BYTES} bytes",
                        "type": ValidationErrorCategory.PAYLOAD_TRUNCATED.value,
                    }
                ],
            },
        )

    record = await persist_raw_envelope(
        db,
        validation_result.envelope,
        processing_status=validation_result.disposition.value,
    )

    # Trigger deterministic normalization only AFTER raw event persistence succeeds.
    # Normalization failure never rolls back or removes the accepted RawEventEnvelope.
    event_id = None
    norm_status = "failed"
    try:
        norm_record = await _default_normalization_service.normalize_and_persist(
            db, record
        )
        event_id = norm_record.event_id
        norm_status = norm_record.normalization_status
    except Exception as exc:
        logger.error(
            "Post-ingest normalization failed for ingestion_id=%s: %s",
            record.ingestion_id,
            type(exc).__name__,
        )

    return EventIngestionResponse(
        ingestion_id=record.ingestion_id,
        event_id=event_id,
        source_type=SourceTypeEnum(record.source_type),
        status=record.processing_status,
        normalization_status=norm_status,
        possible_duplicate=record.possible_duplicate,
        received_at=_format_utc_iso(record.received_at),
        warnings=[w.message for w in validation_result.warnings],
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


@router.get(
    "/normalized",
    status_code=status.HTTP_200_OK,
    response_model=NormalizedEventListResponse,
    summary="List Recently Normalized Security Events",
)
async def get_recent_normalized_events(
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of normalized events to return (1-100)",
    ),
    db: AsyncSession = Depends(get_db),
) -> NormalizedEventListResponse:
    """
    Retrieve recently processed normalized security events in deterministic descending
    order (`created_at DESC, id DESC`). Raw payloads are omitted.
    """
    records = await list_recent_normalized_events(db, limit=limit)
    items = [_to_normalized_response(rec) for rec in records]
    return NormalizedEventListResponse(items=items, count=len(items), limit=limit)


@router.get(
    "/normalized/{event_id}",
    status_code=status.HTTP_200_OK,
    response_model=NormalizedEventResponse,
    summary="Get Normalized Security Event by Event ID",
)
async def get_normalized_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
) -> NormalizedEventResponse:
    """Retrieve a single normalized security event by its stable event_id."""
    record = await get_normalized_event_by_event_id(db, event_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return _to_normalized_response(record)
