"""
AutoSOC - Deterministic Security Event Enrichment Service (Day 9 Reconciled)

Coordinates deterministic observable enrichment (Pranjal's `DeterministicEventEnricher`)
and event-level network/indicator context (DJ's `DeterministicLocalEnricher`) via
`EventEnricherProtocol`, validating against the canonical `EnrichmentResult` contract and
persisting separately in `event_enrichments` without modifying normalized or raw data.
"""

import asyncio
import ipaddress
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.events.enrichment_contract import (
    ENRICHMENT_PIPELINE_VERSION,
    CanonicalEnrichedObservable,
    EnrichmentProvenance,
    EnrichmentResult,
    EnrichmentStatusEnum,
    EventEnrichmentContextSections,
    IndicatorEnrichmentContext,
    NetworkEnrichmentContext,
    NormalizedEventEnrichmentPayload,
    ThreatIntelContext,
    contains_forbidden_raw_keys,
)
from app.events.models import EventEnrichment, NormalizedEvent
from app.events.protocols import EventEnricherProtocol
from app.events.repository import (
    get_event_enrichment_by_event_id,
    get_normalized_event_by_event_id,
    persist_or_update_event_enrichment,
)
from app.threat_intelligence import DeterministicEventEnricher, ThreatIntelOrchestrator

logger = logging.getLogger("autosoc")

# Explicit internal ranges (excludes RFC 5737 / RFC 3849 test-net documentation blocks)
_INTERNAL_IPV4_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
)

_INTERNAL_IPV6_NETWORKS = (
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fe80::/10"),
)


def _classify_ip(value: Optional[str]) -> Tuple[Optional[bool], Optional[int]]:
    if value is None or not str(value).strip():
        return None, None
    try:
        ip_obj = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None, None

    if ip_obj.version == 4:
        is_internal = any(ip_obj in net for net in _INTERNAL_IPV4_NETWORKS)
    else:
        is_internal = any(ip_obj in net for net in _INTERNAL_IPV6_NETWORKS)
    return is_internal, ip_obj.version


def _extract_hash_algorithm(file_hash: Optional[str]) -> Tuple[bool, Optional[str]]:
    if not isinstance(file_hash, str) or not file_hash.strip():
        return False, None
    raw = file_hash.strip()
    if ":" in raw:
        algo, digest = raw.split(":", 1)
        algo_clean = algo.strip().lower()
        if algo_clean in ("md5", "sha1", "sha256", "sha512") and digest.strip():
            return True, algo_clean
    length = len(raw)
    if length == 64:
        return True, "sha256"
    if length == 40:
        return True, "sha1"
    if length == 32:
        return True, "md5"
    return True, None


def _sanitize_validation_errors(exc: ValidationError) -> List[str]:
    messages: List[str] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ()))
        msg = err.get("msg", "Invalid enrichment contract value")
        messages.append(f"{loc}: {msg}" if loc else msg)
    return messages


def _norm_record_to_dict(norm_record: NormalizedEvent) -> Dict[str, Any]:
    return {
        "event_id": norm_record.event_id,
        "ingestion_id": norm_record.ingestion_id,
        "normalization_status": norm_record.normalization_status,
        "timestamp": norm_record.event_timestamp,
        "source_type": norm_record.source_type,
        "sensor_id": norm_record.sensor_id,
        "event_category": norm_record.event_category,
        "event_type": norm_record.event_type,
        "host": norm_record.host,
        "user": norm_record.user_name,
        "source_ip": norm_record.source_ip,
        "destination_ip": norm_record.destination_ip,
        "source_port": norm_record.source_port,
        "destination_port": norm_record.destination_port,
        "protocol": norm_record.protocol,
        "process": norm_record.process,
        "file_hash": norm_record.file_hash,
        "domain": norm_record.domain,
        "command_line": norm_record.command_line,
        "severity": norm_record.severity,
        "metadata": dict(norm_record.event_metadata or {}),
    }


def _extract_event_context(
    normalized_event: Dict[str, Any], warnings: List[str]
) -> Tuple[EventEnrichmentContextSections, List[str]]:
    """Compute DJ's deterministic event-level network & indicator context."""
    enriched_fields: List[str] = []

    src_ip = normalized_event.get("source_ip")
    dst_ip = normalized_event.get("destination_ip")
    dst_port = normalized_event.get("destination_port")
    domain = normalized_event.get("domain")
    file_hash = normalized_event.get("file_hash")
    command_line = normalized_event.get("command_line")

    is_internal_src, src_ver = _classify_ip(src_ip)
    is_internal_dst, dst_ver = _classify_ip(dst_ip)
    if is_internal_src is not None:
        enriched_fields.append("context.network.is_internal_src")
    if is_internal_dst is not None:
        enriched_fields.append("context.network.is_internal_dst")

    is_external_to_internal: Optional[bool] = None
    if is_internal_src is not None and is_internal_dst is not None:
        is_external_to_internal = (not is_internal_src) and is_internal_dst
        enriched_fields.append("context.network.is_external_to_internal")

    dst_port_well_known: Optional[bool] = None
    if isinstance(dst_port, int) and not isinstance(dst_port, bool):
        if 0 <= dst_port <= 65535:
            dst_port_well_known = dst_port <= 1023
            enriched_fields.append("context.network.dst_port_well_known")
        else:
            warnings.append("destination_port out of valid range [0, 65535]")

    network_ctx = NetworkEnrichmentContext(
        is_internal_src=is_internal_src,
        is_internal_dst=is_internal_dst,
        is_external_to_internal=is_external_to_internal,
        src_ip_version=src_ver,
        dst_ip_version=dst_ver,
        dst_port_well_known=dst_port_well_known,
        geo=None,
    )

    domain_length: Optional[int] = None
    domain_tld: Optional[str] = None
    subdomain_count: Optional[int] = None
    if isinstance(domain, str) and domain.strip():
        clean_domain = domain.strip().rstrip(".").lower()
        domain_length = len(clean_domain)
        parts = [p for p in clean_domain.split(".") if p]
        if len(parts) >= 2:
            domain_tld = parts[-1][:64]
            subdomain_count = max(0, len(parts) - 2)
        elif len(parts) == 1:
            subdomain_count = 0
        enriched_fields.extend(
            ["context.indicators.domain_length", "context.indicators.subdomain_count"]
        )
        if domain_tld is not None:
            enriched_fields.append("context.indicators.domain_tld")

    has_file_hash, hash_algo = _extract_hash_algorithm(file_hash)
    if has_file_hash:
        enriched_fields.append("context.indicators.has_file_hash")
        if hash_algo is not None:
            enriched_fields.append("context.indicators.file_hash_algorithm")

    has_command_line = isinstance(command_line, str) and bool(command_line.strip())
    command_line_length = len(command_line) if has_command_line else None
    if has_command_line:
        enriched_fields.extend(
            ["context.indicators.has_command_line", "context.indicators.command_line_length"]
        )

    indicator_ctx = IndicatorEnrichmentContext(
        domain_length=domain_length,
        domain_tld=domain_tld,
        subdomain_count=subdomain_count,
        has_file_hash=has_file_hash,
        file_hash_algorithm=hash_algo,
        has_command_line=has_command_line,
        command_line_length=command_line_length,
    )

    return (
        EventEnrichmentContextSections(
            network=network_ctx,
            indicators=indicator_ctx,
            threat_intel=None,
        ),
        enriched_fields,
    )


def _issue_messages(items: Any) -> List[str]:
    messages: List[str] = []
    if not isinstance(items, list):
        return messages
    for item in items:
        if isinstance(item, str):
            messages.append(item)
        elif isinstance(item, dict) and isinstance(item.get("message"), str):
            messages.append(item["message"])
    return messages


class DeterministicLocalEnricher:
    """
    Canonical Day 9 + Day 10 EventEnricherProtocol implementation combining:
      - Pranjal's `DeterministicEventEnricher` for observable extraction,
        normalization, deduplication, classification, verdicts, and provenance
      - Day 10 `ThreatIntelOrchestrator` for configurable external TI lookups,
        TTL caching, timeouts, and offline fallback
      - DJ's deterministic event-level `context.network` & `context.indicators`
    """

    def __init__(
        self,
        observable_enricher: Optional[DeterministicEventEnricher] = None,
        ti_orchestrator: Optional[ThreatIntelOrchestrator] = None,
    ) -> None:
        self._observable_enricher = observable_enricher or DeterministicEventEnricher()
        self._ti_orchestrator = ti_orchestrator or ThreatIntelOrchestrator(
            settings_obj=settings
        )

    @property
    def PROVIDER_NAME(self) -> str:
        return self._observable_enricher._provider.provider_id

    @property
    def PROVIDER_VERSION(self) -> str:
        return self._observable_enricher._provider.provider_version

    @property
    def ti_orchestrator(self) -> ThreatIntelOrchestrator:
        return self._ti_orchestrator

    async def enrich(self, normalized_event: Dict[str, Any]) -> Dict[str, Any]:
        ti_result = self._observable_enricher.enrich_event(normalized_event)
        ti_outcome = None
        if (
            ti_result.observables
            and ti_result.enrichment_status
            in (EnrichmentStatusEnum.ENRICHED, EnrichmentStatusEnum.ENRICHED_PARTIAL)
        ):
            ti_outcome = await self._ti_orchestrator.enrich_observables(
                ti_result.observables,
                ingestion_id=str(ti_result.ingestion_id or normalized_event["ingestion_id"]),
                source_event_id=ti_result.source_event_id,
            )
            obs_models = ti_outcome.observables
            live_lookup = bool(ti_result.live_lookup_performed or ti_outcome.live_lookup_performed)
            ti_warnings = _issue_messages(
                [w.model_dump() for w in ti_result.warnings]
                + [w.model_dump() for w in ti_outcome.warnings]
            )
            ti_errors = _issue_messages([e.model_dump() for e in ti_result.errors])
        else:
            obs_models = ti_result.observables
            live_lookup = ti_result.live_lookup_performed
            ti_warnings = _issue_messages([w.model_dump() for w in ti_result.warnings])
            ti_errors = _issue_messages([e.model_dump() for e in ti_result.errors])

        extra_warnings: List[str] = []
        event_context, context_fields = _extract_event_context(
            normalized_event, extra_warnings
        )
        if ti_outcome is not None and ti_outcome.threat_intel_context is not None:
            event_context = event_context.model_copy(
                update={"threat_intel": ThreatIntelContext(**ti_outcome.threat_intel_context)}
            )
            context_fields.append("context.threat_intel")

        warnings = ti_warnings + extra_warnings
        errors = ti_errors

        obs_list = [
            CanonicalEnrichedObservable(**obs.model_dump()) for obs in obs_models
        ]
        for obs in obs_list:
            for field in obs.provenance.source_fields:
                key = f"observable:{obs.observable_type.value}:{field}"
                if key not in context_fields:
                    context_fields.append(key)

        status = ti_result.enrichment_status
        if status == EnrichmentStatusEnum.ENRICHED and (
            extra_warnings or (ti_outcome is not None and ti_outcome.has_partial_failures)
        ):
            status = EnrichmentStatusEnum.ENRICHED_PARTIAL

        payload = NormalizedEventEnrichmentPayload(
            observable_count=len(obs_list),
            observables=obs_list,
            context=event_context,
        )

        provenance = EnrichmentProvenance(
            pipeline_version=ENRICHMENT_PIPELINE_VERSION,
            provider=ti_result.provider,
            provider_version=ti_result.provider_version,
            live_lookup_performed=live_lookup,
            enriched_fields=context_fields,
            source_event_id=str(normalized_event["event_id"]),
            source_ingestion_id=str(normalized_event["ingestion_id"]),
        )

        result = EnrichmentResult(
            status=status,
            provider=ti_result.provider,
            provider_version=ti_result.provider_version,
            live_lookup_performed=live_lookup,
            provenance=provenance,
            enrichment_data=payload,
            warnings=warnings,
            errors=errors,
        )
        return result.model_dump()


class EnrichmentService:
    """
    Application service orchestrating deterministic enrichment of NormalizedEvent
    records and storing results separately in `event_enrichments`.
    """

    def __init__(self, enricher: Optional[EventEnricherProtocol] = None) -> None:
        self._enricher: EventEnricherProtocol = enricher or DeterministicLocalEnricher()

    async def enrich_by_event_id(
        self, session: AsyncSession, event_id: str, *, retry: bool = False
    ) -> Optional[EventEnrichment]:
        """Look up a NormalizedEvent by event_id and enrich it safely."""
        norm_record = await get_normalized_event_by_event_id(session, event_id)
        if norm_record is None:
            return None
        return await self.enrich_normalized_event(session, norm_record, retry=retry)

    @staticmethod
    def _coerce_provider_output(
        raw_output: Dict[str, Any], norm_record: NormalizedEvent
    ) -> EnrichmentResult:
        """
        Validate provider output into canonical `EnrichmentResult`.
        Also accepts direct `app.threat_intelligence.EventEnrichmentResult` dicts
        from `DeterministicEventEnricher`.
        """
        if "enrichment_status" in raw_output and "status" not in raw_output:
            provider = str(raw_output.get("provider") or "deterministic_local_ti")
            provider_ver = str(raw_output.get("provider_version") or "1.0.0")
            live_lookup = bool(raw_output.get("live_lookup_performed", False))
            observables = [
                CanonicalEnrichedObservable(**obs)
                for obs in (raw_output.get("observables") or [])
            ]
            event_ctx, fields = _extract_event_context(
                _norm_record_to_dict(norm_record), []
            )
            return EnrichmentResult(
                status=EnrichmentStatusEnum(raw_output["enrichment_status"]),
                provider=provider,
                provider_version=provider_ver,
                live_lookup_performed=live_lookup,
                provenance=EnrichmentProvenance(
                    pipeline_version=ENRICHMENT_PIPELINE_VERSION,
                    provider=provider,
                    provider_version=provider_ver,
                    live_lookup_performed=live_lookup,
                    enriched_fields=fields,
                    source_event_id=str(norm_record.event_id),
                    source_ingestion_id=norm_record.ingestion_id,
                ),
                enrichment_data=NormalizedEventEnrichmentPayload(
                    observable_count=len(observables),
                    observables=observables,
                    context=event_ctx,
                ),
                warnings=_issue_messages(raw_output.get("warnings")),
                errors=_issue_messages(raw_output.get("errors")),
            )

        return EnrichmentResult(**raw_output)

    async def enrich_normalized_event(
        self,
        session: AsyncSession,
        norm_record: NormalizedEvent,
        *,
        retry: bool = False,
    ) -> Optional[EventEnrichment]:
        """
        Deterministically enrich a normalized security event and store or update
        its EventEnrichment record without modifying raw or normalized tables.
        """
        if not norm_record.event_id:
            return None

        existing = await get_event_enrichment_by_event_id(
            session, norm_record.event_id
        )
        if existing is not None and not retry:
            return existing

        now_utc = datetime.now(timezone.utc)
        norm_dict = _norm_record_to_dict(norm_record)
        default_provider = str(
            getattr(self._enricher, "PROVIDER_NAME", type(self._enricher).__name__)
        )
        default_provider_ver = str(getattr(self._enricher, "PROVIDER_VERSION", "1.0.0"))

        validated_result: Optional[EnrichmentResult] = None
        failure_errors: List[str] = []

        try:
            raw_output = await self._enricher.enrich(norm_dict)
            if contains_forbidden_raw_keys(raw_output):
                failure_errors = [
                    "Enrichment provider output rejected: forbidden raw payload key present"
                ]
            else:
                validated_result = self._coerce_provider_output(raw_output, norm_record)
        except ValidationError as exc:
            failure_errors = _sanitize_validation_errors(exc)
        except asyncio.TimeoutError:
            failure_errors = ["Enrichment provider timeout"]
        except Exception as exc:
            logger.warning(
                "Enricher raised %s for event_id=%s",
                type(exc).__name__,
                norm_record.event_id,
            )
            failure_errors = [f"Enrichment provider error: {type(exc).__name__}"]

        if validated_result is None or validated_result.status == EnrichmentStatusEnum.FAILED:
            errors = (
                list(validated_result.errors)
                if validated_result and validated_result.errors
                else (failure_errors or ["Enrichment failed"])
            )
            warnings = list(validated_result.warnings) if validated_result else []

            # Preserve previously persisted valid enrichment data if a manual retry fails/times out
            has_existing_valid_data = (
                existing is not None
                and bool(existing.enrichment_data)
                and existing.enrichment_status != EnrichmentStatusEnum.FAILED.value
            )
            if has_existing_valid_data and existing is not None:
                preserved_warnings = list(existing.enrichment_warnings or [])
                for err in errors:
                    msg = f"Retry failed (existing context preserved): {err}"
                    if msg not in preserved_warnings:
                        preserved_warnings.append(msg)
                return await self._upsert_enrichment(
                    session,
                    norm_record=norm_record,
                    existing=existing,
                    provider=existing.provider,
                    enrichment_status=EnrichmentStatusEnum.ENRICHED_PARTIAL.value,
                    enrichment_data=dict(existing.enrichment_data),
                    provenance=dict(existing.provenance or {}),
                    warnings=preserved_warnings,
                    errors=errors,
                    enriched_at=existing.enriched_at,
                    now_utc=now_utc,
                )

            prov = (
                validated_result.provenance.model_dump()
                if validated_result
                else {
                    "pipeline_version": ENRICHMENT_PIPELINE_VERSION,
                    "provider": default_provider,
                    "provider_version": default_provider_ver,
                    "live_lookup_performed": False,
                    "enriched_fields": [],
                    "source_event_id": norm_record.event_id,
                    "source_ingestion_id": norm_record.ingestion_id,
                }
            )
            return await self._upsert_enrichment(
                session,
                norm_record=norm_record,
                existing=existing,
                provider=validated_result.provider if validated_result else default_provider,
                enrichment_status=EnrichmentStatusEnum.FAILED.value,
                enrichment_data={},
                provenance=prov,
                warnings=warnings,
                errors=errors,
                enriched_at=None,
                now_utc=now_utc,
            )

        data_dict = (
            validated_result.enrichment_data.model_dump()
            if validated_result.enrichment_data is not None
            else {}
        )
        enriched_at = (
            now_utc
            if validated_result.status
            in (
                EnrichmentStatusEnum.ENRICHED,
                EnrichmentStatusEnum.ENRICHED_PARTIAL,
                EnrichmentStatusEnum.NO_OBSERVABLES,
            )
            else None
        )
        return await self._upsert_enrichment(
            session,
            norm_record=norm_record,
            existing=existing,
            provider=validated_result.provider,
            enrichment_status=validated_result.status.value,
            enrichment_data=data_dict,
            provenance=validated_result.provenance.model_dump(),
            warnings=list(validated_result.warnings),
            errors=list(validated_result.errors),
            enriched_at=enriched_at,
            now_utc=now_utc,
        )

    @staticmethod
    async def _upsert_enrichment(
        session: AsyncSession,
        *,
        norm_record: NormalizedEvent,
        existing: Optional[EventEnrichment],
        provider: str,
        enrichment_status: str,
        enrichment_data: Dict[str, Any],
        provenance: Dict[str, Any],
        warnings: List[str],
        errors: List[str],
        enriched_at: Optional[datetime],
        now_utc: datetime,
    ) -> EventEnrichment:
        assert norm_record.event_id is not None
        if existing is not None:
            existing.provider = provider
            existing.enrichment_status = enrichment_status
            existing.enrichment_data = enrichment_data
            existing.provenance = provenance
            existing.enrichment_warnings = warnings
            existing.enrichment_errors = errors
            existing.attempt_count = int(existing.attempt_count or 1) + 1
            existing.enriched_at = enriched_at
            existing.updated_at = now_utc
            return await persist_or_update_event_enrichment(session, existing)

        record = EventEnrichment(
            enrichment_id=str(uuid.uuid4()),
            normalized_event_row_id=norm_record.id,
            event_id=norm_record.event_id,
            ingestion_id=norm_record.ingestion_id,
            provider=provider,
            enrichment_status=enrichment_status,
            enrichment_data=enrichment_data,
            provenance=provenance,
            enrichment_warnings=warnings,
            enrichment_errors=errors,
            attempt_count=1,
            enriched_at=enriched_at,
            created_at=now_utc,
            updated_at=now_utc,
        )
        return await persist_or_update_event_enrichment(session, record)
