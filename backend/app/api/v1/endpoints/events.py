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
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.events.api_schemas import (
    EventEnrichmentListResponse,
    EventEnrichmentQueryParams,
    EventEnrichmentResponse,
    EventIngestionResponse,
    IngestedEventListResponse,
    IngestedEventSummary,
    NormalizedEventListResponse,
    NormalizedEventResponse,
    build_payload_preview,
)
from app.events.enrichment_contract import (
    ENRICHMENT_PIPELINE_VERSION,
    EnrichmentProvenance,
    EnrichmentStatusEnum,
    MAX_PROVIDER_NAME_LENGTH,
    NormalizedEventEnrichmentPayload,
)
from app.events.enrichment_service import EnrichmentService
from app.events.models import EventEnrichment, NormalizedEvent
from app.events.normalization_service import NormalizationService
from app.events.query_contract import (
    DEFAULT_QUERY_LIMIT,
    DEFAULT_QUERY_OFFSET,
    MAX_EVENT_TYPE_LENGTH,
    MAX_QUERY_LIMIT,
    MAX_QUERY_OFFSET,
    MAX_SEARCH_LENGTH,
    NormalizedEventQueryParams,
    NormalizedEventSortField,
    SortOrderEnum,
)
from app.events.repository import (
    get_event_enrichment_by_event_id,
    get_event_enrichments_by_event_ids,
    get_normalized_event_by_event_id,
    list_recent_envelopes,
    persist_raw_envelope,
    query_event_enrichments,
    query_normalized_events,
)
from app.events.schemas import (
    EventCategoryEnum,
    IngestionEnvelope,
    NormalizationStatusEnum,
    SourceTypeEnum,
)
from app.events.validation import (
    MAX_RAW_PAYLOAD_BYTES,
    ValidationErrorCategory,
    validate_ingestion_envelope,
)

logger = logging.getLogger("autosoc")

router = APIRouter()
_default_normalization_service = NormalizationService()
_default_enrichment_service = EnrichmentService()


def _format_utc_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _to_enrichment_response(rec: EventEnrichment) -> EventEnrichmentResponse:
    raw_prov = rec.provenance or {}
    provider_version = str(raw_prov.get("provider_version") or "1.0.0")
    live_lookup = bool(raw_prov.get("live_lookup_performed", False))
    provenance = EnrichmentProvenance(
        pipeline_version=str(raw_prov.get("pipeline_version") or ENRICHMENT_PIPELINE_VERSION),
        provider=str(raw_prov.get("provider") or rec.provider),
        provider_version=provider_version,
        live_lookup_performed=live_lookup,
        enriched_fields=list(raw_prov.get("enriched_fields") or []),
        source_event_id=str(raw_prov.get("source_event_id") or rec.event_id),
        source_ingestion_id=str(raw_prov.get("source_ingestion_id") or rec.ingestion_id),
    )
    enrichment_payload = (
        NormalizedEventEnrichmentPayload(**rec.enrichment_data)
        if rec.enrichment_data
        else None
    )
    observables = enrichment_payload.observables if enrichment_payload else []
    observable_count = (
        enrichment_payload.observable_count if enrichment_payload else 0
    )
    context = enrichment_payload.context if enrichment_payload else None
    return EventEnrichmentResponse(
        enrichment_id=rec.enrichment_id,
        event_id=rec.event_id,
        ingestion_id=rec.ingestion_id,
        provider=rec.provider,
        provider_version=provider_version,
        enrichment_status=EnrichmentStatusEnum(rec.enrichment_status),
        live_lookup_performed=live_lookup,
        observable_count=observable_count,
        observables=observables,
        context=context,
        enrichment_data=enrichment_payload,
        provenance=provenance,
        warnings=list(rec.enrichment_warnings or []),
        errors=list(rec.enrichment_errors or []),
        attempt_count=int(rec.attempt_count or 1),
        enriched_at=_format_utc_iso(rec.enriched_at) if rec.enriched_at is not None else None,
        created_at=_format_utc_iso(rec.created_at),
        updated_at=_format_utc_iso(rec.updated_at),
    )


def _to_normalized_response(
    rec: NormalizedEvent, enrichment_rec: Optional[EventEnrichment] = None
) -> NormalizedEventResponse:
    enrichment_dto = (
        _to_enrichment_response(enrichment_rec)
        if enrichment_rec is not None
        else None
    )
    if enrichment_dto is not None:
        enrichment_status: Optional[str] = enrichment_dto.enrichment_status.value
    elif rec.event_id is None:
        enrichment_status = EnrichmentStatusEnum.SKIPPED.value
    else:
        enrichment_status = None

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
        enrichment_status=enrichment_status,
        enrichment=enrichment_dto,
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
    enrichment_status: Optional[str] = None
    norm_record: Optional[NormalizedEvent] = None
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

    if event_id is not None and norm_record is not None:
        try:
            enrich_record = await _default_enrichment_service.enrich_normalized_event(
                db, norm_record
            )
            if enrich_record is not None:
                enrichment_status = enrich_record.enrichment_status
        except Exception as exc:
            enrichment_status = EnrichmentStatusEnum.FAILED.value
            logger.error(
                "Post-ingest enrichment failed for ingestion_id=%s: %s",
                record.ingestion_id,
                type(exc).__name__,
            )

    return EventIngestionResponse(
        ingestion_id=record.ingestion_id,
        event_id=event_id,
        source_type=SourceTypeEnum(record.source_type),
        status=record.processing_status,
        normalization_status=norm_status,
        enrichment_status=enrichment_status,
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
    summary="Query and Paginate Normalized Security Events",
)
async def get_recent_normalized_events(
    limit: int = Query(
        default=DEFAULT_QUERY_LIMIT,
        ge=1,
        le=MAX_QUERY_LIMIT,
        description="Maximum number of normalized events to return per page (1-100)",
    ),
    offset: int = Query(
        default=DEFAULT_QUERY_OFFSET,
        ge=0,
        le=MAX_QUERY_OFFSET,
        description="Number of matching normalized events to skip (0-10000)",
    ),
    source_type: Optional[SourceTypeEnum] = Query(
        default=None,
        description="Filter by telemetry source_type",
    ),
    normalization_status: Optional[NormalizationStatusEnum] = Query(
        default=None,
        description="Filter by normalization_status",
    ),
    event_category: Optional[EventCategoryEnum] = Query(
        default=None,
        description="Filter by normalized event_category",
    ),
    event_type: Optional[str] = Query(
        default=None,
        max_length=MAX_EVENT_TYPE_LENGTH,
        description="Filter by canonical lowercase dot-notation event_type (e.g. alert.ids, process.create)",
    ),
    severity: Optional[int] = Query(
        default=None,
        ge=1,
        le=5,
        description="Filter by exact severity level (1-5)",
    ),
    start_time: Optional[str] = Query(
        default=None,
        description="Filter normalized event_timestamp >= start_time (ISO 8601 with timezone)",
    ),
    end_time: Optional[str] = Query(
        default=None,
        description="Filter normalized event_timestamp <= end_time (ISO 8601 with timezone)",
    ),
    search: Optional[str] = Query(
        default=None,
        max_length=MAX_SEARCH_LENGTH,
        description="Case-insensitive literal substring search across approved normalized fields",
    ),
    sort_by: NormalizedEventSortField = Query(
        default=NormalizedEventSortField.CREATED_AT,
        description="Allowlisted column to sort normalized events by",
    ),
    sort_order: SortOrderEnum = Query(
        default=SortOrderEnum.DESC,
        description="Sort direction (asc or desc)",
    ),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Query normalized security events at the database level with canonical contract
    validation (`query_contract.NormalizedEventQueryParams`), SQL filtering, search,
    deterministic sorting, and offset pagination. Raw payloads are omitted.
    """
    try:
        query_params = NormalizedEventQueryParams(
            limit=limit,
            offset=offset,
            source_type=source_type,
            normalization_status=normalization_status,
            event_category=event_category,
            event_type=event_type,
            severity=severity,
            start_time=start_time,
            end_time=end_time,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
        )
    except ValidationError as exc:
        errors = [
            {
                "field": " -> ".join(["query", *(str(loc) for loc in err.get("loc", []))]),
                "message": err.get("msg", ""),
                "type": err.get("type", ""),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"message": "Validation error", "errors": errors},
        )

    records, total = await query_normalized_events(db, query_params)
    event_ids = [rec.event_id for rec in records if rec.event_id]
    enrichment_map = await get_event_enrichments_by_event_ids(db, event_ids)
    items = [
        _to_normalized_response(
            rec, enrichment_map.get(rec.event_id) if rec.event_id else None
        )
        for rec in records
    ]
    return NormalizedEventListResponse(
        items=items,
        count=len(items),
        total=total,
        limit=query_params.limit,
        offset=query_params.offset,
        has_more=(query_params.offset + len(items)) < total,
    )


@router.get(
    "/enrichments",
    status_code=status.HTTP_200_OK,
    response_model=EventEnrichmentListResponse,
    summary="Query and Paginate Normalized Event Enrichments",
)
async def list_event_enrichments(
    limit: int = Query(
        default=DEFAULT_QUERY_LIMIT,
        ge=1,
        le=MAX_QUERY_LIMIT,
        description="Maximum number of enrichment records to return per page (1-100)",
    ),
    offset: int = Query(
        default=DEFAULT_QUERY_OFFSET,
        ge=0,
        le=MAX_QUERY_OFFSET,
        description="Number of matching enrichment records to skip (0-10000)",
    ),
    enrichment_status: Optional[EnrichmentStatusEnum] = Query(
        default=None,
        description="Filter by enrichment_status",
    ),
    provider: Optional[str] = Query(
        default=None,
        max_length=MAX_PROVIDER_NAME_LENGTH,
        description="Filter by enrichment provider name",
    ),
    sort_order: SortOrderEnum = Query(
        default=SortOrderEnum.DESC,
        description="Sort direction by created_at (asc or desc)",
    ),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """List persisted security event enrichments with bounded offset pagination."""
    try:
        query_params = EventEnrichmentQueryParams(
            limit=limit,
            offset=offset,
            enrichment_status=enrichment_status,
            provider=provider,
            sort_order=sort_order,
        )
    except ValidationError as exc:
        errors = [
            {
                "field": " -> ".join(["query", *(str(loc) for loc in err.get("loc", []))]),
                "message": err.get("msg", ""),
                "type": err.get("type", ""),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"message": "Validation error", "errors": errors},
        )

    records, total = await query_event_enrichments(
        db,
        limit=query_params.limit,
        offset=query_params.offset,
        enrichment_status=query_params.enrichment_status,
        provider=query_params.provider,
        sort_order=query_params.sort_order,
    )
    items = [_to_enrichment_response(rec) for rec in records]
    return EventEnrichmentListResponse(
        items=items,
        count=len(items),
        total=total,
        limit=query_params.limit,
        offset=query_params.offset,
        has_more=(query_params.offset + len(items)) < total,
    )


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
    enrichment_rec = await get_event_enrichment_by_event_id(db, event_id)
    return _to_normalized_response(record, enrichment_rec)


@router.get(
    "/normalized/{event_id}/enrichment",
    status_code=status.HTTP_200_OK,
    response_model=EventEnrichmentResponse,
    summary="Get Enrichment Context for a Normalized Event",
)
async def get_normalized_event_enrichment(
    event_id: str,
    db: AsyncSession = Depends(get_db),
) -> EventEnrichmentResponse:
    """Retrieve the enrichment record associated with a normalized event_id."""
    record = await get_event_enrichment_by_event_id(db, event_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return _to_enrichment_response(record)


@router.post(
    "/normalized/{event_id}/enrich",
    status_code=status.HTTP_200_OK,
    response_model=EventEnrichmentResponse,
    summary="Enrich or Retry Enrichment for a Normalized Event",
)
async def trigger_normalized_event_enrichment(
    event_id: str,
    force_retry: bool = Query(
        default=False,
        description="Retry enrichment even if already completed or failed",
    ),
    db: AsyncSession = Depends(get_db),
) -> EventEnrichmentResponse:
    """
    Deterministically enrich a persisted NormalizedEvent by event_id, or retry
    a failed enrichment in place without creating duplicate enrichment records.
    """
    norm_record = await get_normalized_event_by_event_id(db, event_id)
    if norm_record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    existing = await get_event_enrichment_by_event_id(db, event_id)
    should_retry = force_retry or (
        existing is not None
        and existing.enrichment_status == EnrichmentStatusEnum.FAILED.value
    )
    record = await _default_enrichment_service.enrich_normalized_event(
        db, norm_record, retry=should_retry
    )
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return _to_enrichment_response(record)
