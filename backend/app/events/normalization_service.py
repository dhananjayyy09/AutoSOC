"""
AutoSOC - Deterministic Security Event Normalization Service (Day 7)

Coordinates retrieval of an accepted RawEventEnvelope, deterministic parsing
(SourceParserProtocol -> DeterministicSourceParser), deterministic normalization
(EventNormalizerProtocol -> DeterministicEventNormalizer), contract validation
against NormalizedSecurityEvent (plus optional EventValidatorProtocol), and
persistence of the NormalizedEvent record without mutating or deleting the
immutable raw source evidence.
"""

import logging
from typing import Any, Dict, List, Optional

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.events.models import NormalizedEvent, RawEventEnvelope
from app.events.normalizer import DeterministicEventNormalizer, NormalizationResult
from app.events.parser import DeterministicSourceParser
from app.events.protocols import (
    EventNormalizerProtocol,
    EventValidatorProtocol,
    SourceParserProtocol,
)
from app.events.repository import (
    get_normalized_event_by_ingestion_id,
    get_raw_envelope_by_ingestion_id,
    persist_normalized_event,
)
from app.events.schemas import (
    NormalizationStatusEnum,
    NormalizedSecurityEvent,
    SourceTypeEnum,
)

logger = logging.getLogger("autosoc")

_UNSUPPORTED_SOURCES = {
    SourceTypeEnum.CUSTOM.value,
    SourceTypeEnum.WINDOWS_EVENT_LOG.value,
    SourceTypeEnum.AUDITD.value,
    SourceTypeEnum.OSQUERY.value,
}


def _sanitize_validation_errors(exc: ValidationError) -> List[str]:
    messages: List[str] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ()))
        msg = err.get("msg", "Invalid value")
        messages.append(f"{loc}: {msg}" if loc else msg)
    return messages


def _envelope_dict_from_raw(raw_envelope: RawEventEnvelope) -> Dict[str, Any]:
    return {
        "ingestion_id": raw_envelope.ingestion_id,
        "source_type": raw_envelope.source_type,
        "sensor_id": raw_envelope.sensor_id,
        "ingest_time": raw_envelope.ingest_time,
        "raw_hash": raw_envelope.raw_hash,
        "raw_payload": raw_envelope.raw_payload,
    }


def _build_outcome_record(
    raw_envelope: RawEventEnvelope,
    *,
    normalization_status: str,
    errors: Optional[List[str]] = None,
    warnings: Optional[List[str]] = None,
    partial: Optional[Dict[str, Any]] = None,
) -> NormalizedEvent:
    partial_data = partial or {}
    return NormalizedEvent(
        event_id=None,
        raw_envelope_id=raw_envelope.id,
        ingestion_id=raw_envelope.ingestion_id,
        source_type=raw_envelope.source_type,
        sensor_id=raw_envelope.sensor_id,
        event_timestamp=partial_data.get("timestamp")
        if isinstance(partial_data.get("timestamp"), str)
        else None,
        event_category=partial_data.get("event_category")
        if isinstance(partial_data.get("event_category"), str)
        else None,
        event_type=partial_data.get("event_type")
        if isinstance(partial_data.get("event_type"), str)
        else None,
        host=partial_data.get("host")
        if isinstance(partial_data.get("host"), str)
        else None,
        event_metadata=partial_data.get("metadata")
        if isinstance(partial_data.get("metadata"), dict)
        else {
            "ingest_time": raw_envelope.ingest_time,
            "raw_hash": raw_envelope.raw_hash,
        },
        normalization_status=normalization_status,
        normalization_errors=list(errors or []),
        normalization_warnings=list(warnings or []),
    )


class NormalizationService:
    """
    Application service orchestrating deterministic security-event normalization:
      1. Retrieve accepted raw event (when invoked by ingestion_id)
      2. Parse raw_payload via SourceParserProtocol
      3. Normalize parsed fields via EventNormalizerProtocol
      4. Validate against NormalizedSecurityEvent (+ optional EventValidatorProtocol)
      5. Persist NormalizedEvent outcome (success, warning, failure, or unsupported)
         without altering RawEventEnvelope
    """

    def __init__(
        self,
        parser: Optional[SourceParserProtocol] = None,
        normalizer: Optional[EventNormalizerProtocol] = None,
        validator: Optional[EventValidatorProtocol] = None,
    ) -> None:
        self._parser: SourceParserProtocol = parser or DeterministicSourceParser()
        self._normalizer: EventNormalizerProtocol = normalizer or DeterministicEventNormalizer(
            parser=self._parser
            if isinstance(self._parser, DeterministicSourceParser)
            else None
        )
        self._validator: Optional[EventValidatorProtocol] = validator

    async def normalize_by_ingestion_id(
        self, session: AsyncSession, ingestion_id: str
    ) -> Optional[NormalizedEvent]:
        """Retrieve an accepted raw envelope by ingestion_id and normalize it."""
        raw_envelope = await get_raw_envelope_by_ingestion_id(session, ingestion_id)
        if raw_envelope is None:
            return None
        return await self.normalize_and_persist(session, raw_envelope)

    async def normalize_and_persist(
        self, session: AsyncSession, raw_envelope: RawEventEnvelope
    ) -> NormalizedEvent:
        """
        Deterministically normalize a persisted RawEventEnvelope and store the
        resulting NormalizedEvent record (or failure/unsupported outcome).
        Idempotent on `ingestion_id`: returns existing record if already normalized.
        """
        existing = await get_normalized_event_by_ingestion_id(
            session, raw_envelope.ingestion_id
        )
        if existing is not None:
            return existing

        envelope_dict = _envelope_dict_from_raw(raw_envelope)

        if isinstance(self._parser, DeterministicSourceParser) and isinstance(
            self._normalizer, DeterministicEventNormalizer
        ):
            return await self._normalize_with_deterministic_pipeline(
                session, raw_envelope, envelope_dict
            )

        return await self._normalize_with_custom_protocols(
            session, raw_envelope, envelope_dict
        )

    async def _normalize_with_deterministic_pipeline(
        self,
        session: AsyncSession,
        raw_envelope: RawEventEnvelope,
        envelope_dict: Dict[str, Any],
    ) -> NormalizedEvent:
        assert isinstance(self._normalizer, DeterministicEventNormalizer)
        try:
            result: NormalizationResult = self._normalizer.normalize_envelope(
                envelope_dict,
                verify_raw_hash=False,
            )
        except Exception as exc:
            logger.warning(
                "Deterministic normalizer raised %s for ingestion_id=%s",
                type(exc).__name__,
                raw_envelope.ingestion_id,
            )
            failed_record = _build_outcome_record(
                raw_envelope,
                normalization_status=NormalizationStatusEnum.FAILED.value,
                errors=[f"Normalization error: {type(exc).__name__}"],
            )
            return await persist_normalized_event(session, failed_record)

        warnings = [issue.message for issue in result.warnings]
        if result.event is None:
            errors = [issue.message for issue in result.errors]
            if not errors:
                errors = ["Normalization failed"]
            failed_record = _build_outcome_record(
                raw_envelope,
                normalization_status=result.normalization_status.value,
                errors=errors,
                warnings=warnings,
            )
            return await persist_normalized_event(session, failed_record)

        return await self._validate_and_persist_normalized(
            session,
            raw_envelope,
            result.event.model_dump(),
            warnings=warnings,
        )

    async def _normalize_with_custom_protocols(
        self,
        session: AsyncSession,
        raw_envelope: RawEventEnvelope,
        envelope_dict: Dict[str, Any],
    ) -> NormalizedEvent:
        parse_ok, parsed_fields, parse_error = self._parser.parse(
            raw_envelope.raw_payload, raw_envelope.source_type
        )
        if not parse_ok or parsed_fields is None:
            is_unsupported = (
                raw_envelope.source_type in _UNSUPPORTED_SOURCES
                or (parse_error is not None and "unsupported" in parse_error.lower())
            )
            status_val = (
                NormalizationStatusEnum.UNSUPPORTED.value
                if is_unsupported
                else NormalizationStatusEnum.FAILED.value
            )
            failed_record = _build_outcome_record(
                raw_envelope,
                normalization_status=status_val,
                errors=[parse_error or "Source parsing failed"],
            )
            return await persist_normalized_event(session, failed_record)

        try:
            normalized_dict = self._normalizer.normalize(parsed_fields, envelope_dict)
        except Exception as exc:
            logger.warning(
                "Normalizer raised %s for ingestion_id=%s",
                type(exc).__name__,
                raw_envelope.ingestion_id,
            )
            failed_record = _build_outcome_record(
                raw_envelope,
                normalization_status=NormalizationStatusEnum.FAILED.value,
                errors=[f"Normalization error: {type(exc).__name__}"],
            )
            return await persist_normalized_event(session, failed_record)

        return await self._validate_and_persist_normalized(
            session, raw_envelope, normalized_dict, warnings=[]
        )

    async def _validate_and_persist_normalized(
        self,
        session: AsyncSession,
        raw_envelope: RawEventEnvelope,
        normalized_dict: Dict[str, Any],
        *,
        warnings: List[str],
    ) -> NormalizedEvent:
        try:
            validated_model = NormalizedSecurityEvent(**normalized_dict)
        except ValidationError as exc:
            failed_record = _build_outcome_record(
                raw_envelope,
                normalization_status=NormalizationStatusEnum.FAILED.value,
                errors=_sanitize_validation_errors(exc),
                warnings=warnings,
                partial=normalized_dict,
            )
            return await persist_normalized_event(session, failed_record)

        dumped = validated_model.model_dump()

        if self._validator is not None:
            disposition, val_messages = await self._validator.validate(dumped)
            if disposition in ("rejected", "unsupported"):
                failed_record = _build_outcome_record(
                    raw_envelope,
                    normalization_status=(
                        NormalizationStatusEnum.UNSUPPORTED.value
                        if disposition == "unsupported"
                        else NormalizationStatusEnum.FAILED.value
                    ),
                    errors=list(val_messages),
                    warnings=warnings,
                    partial=dumped,
                )
                return await persist_normalized_event(session, failed_record)
            if disposition == "accepted_with_warnings":
                warnings.extend(val_messages)

        norm_status = (
            NormalizationStatusEnum.NORMALIZED_WITH_WARNINGS.value
            if warnings
            else NormalizationStatusEnum.NORMALIZED.value
        )
        record = NormalizedEvent(
            event_id=dumped["event_id"],
            raw_envelope_id=raw_envelope.id,
            ingestion_id=raw_envelope.ingestion_id,
            event_timestamp=dumped["timestamp"],
            source_type=dumped["source"],
            sensor_id=raw_envelope.sensor_id,
            event_category=dumped["event_category"],
            event_type=dumped["event_type"],
            host=dumped["host"],
            user_name=dumped.get("user"),
            source_ip=dumped.get("source_ip"),
            destination_ip=dumped.get("destination_ip"),
            source_port=dumped.get("source_port"),
            destination_port=dumped.get("destination_port"),
            protocol=dumped.get("protocol"),
            process=dumped.get("process"),
            file_hash=dumped.get("file_hash"),
            domain=dumped.get("domain"),
            command_line=dumped.get("command_line"),
            severity=dumped["severity"],
            event_metadata=dumped["metadata"],
            normalization_status=norm_status,
            normalization_errors=[],
            normalization_warnings=warnings,
        )
        return await persist_normalized_event(session, record)
