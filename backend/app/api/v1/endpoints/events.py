"""
AutoSOC API v1 - Security Event Ingestion and Retrieval Endpoints

Exposes minimal, contract-validated endpoints for accepting raw IngestionEnvelopes
into PostgreSQL (using Pranjal's ingestion validation service) and retrieving
bounded recent ingestion summaries.
"""

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Body, Depends, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.events.api_schemas import (
    EventIngestionResponse,
    IngestedEventListResponse,
    IngestedEventSummary,
    build_payload_preview,
)
from app.events.repository import list_recent_envelopes, persist_raw_envelope
from app.events.schemas import IngestionEnvelope, SourceTypeEnum
from app.events.validation import (
    MAX_RAW_PAYLOAD_BYTES,
    ValidationErrorCategory,
    validate_ingestion_envelope,
)

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
    validate it via the security ingestion validation service, and persist it
    unmodified in PostgreSQL.
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

    # Raw storage preserves unmodified payloads up to 64 KiB; until truncation-on-ingest
    # is persisted with a raw_truncated column, reject oversized payloads at the API boundary.
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
    return EventIngestionResponse(
        ingestion_id=record.ingestion_id,
        source_type=SourceTypeEnum(record.source_type),
        status=record.processing_status,
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
