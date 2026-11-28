"""
AutoSOC - Threat Intelligence Observable Pipeline & Normalization Adapter (Day 10)

Connects `DeterministicEventEnricher` (Day 9 local baseline) with one or more
`ThreatIntelProviderProtocol` providers while preserving:
- Minimal observable-only lookup requests (never sends raw events or secrets)
- Conservative verdict resolution (`unknown` when no evidence or conflicting verdicts)
- Full provenance across source fields and providers
- Partial enrichment results when individual providers or observables fail
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple

from app.events.validation import ValidationErrorCategory, ValidationIssue
from app.threat_intelligence.enricher import DeterministicEventEnricher
from app.threat_intelligence.mock_adapter import FixtureThreatIntelProvider
from app.threat_intelligence.provider_contract import (
    ObservableLookupRequest,
    ObservableLookupResult,
    ProviderLookupStatusEnum,
    ThreatIntelProviderProtocol,
    utc_now_iso,
)
from app.threat_intelligence.reliability import (
    OPERATIONAL_FAILURE_STATUS_VALUES,
    ProviderCircuitBreaker,
    RetryPolicy,
    deduplicate_references,
    execute_lookup_with_reliability,
    validate_safe_provider_request,
)
from app.threat_intelligence.schemas import (
    EnrichedObservable,
    EnrichmentProvenance,
    EnrichmentStatusEnum,
    EventEnrichmentResult,
    ObservableTypeEnum,
    ObservableVerdictEnum,
)

_FAILURE_STATUSES = frozenset(
    {
        ProviderLookupStatusEnum.UNAVAILABLE,
        ProviderLookupStatusEnum.TIMEOUT,
        ProviderLookupStatusEnum.RATE_LIMITED,
        ProviderLookupStatusEnum.RETRY_EXHAUSTED,
        ProviderLookupStatusEnum.CIRCUIT_OPEN,
        ProviderLookupStatusEnum.PROVIDER_DISABLED,
        ProviderLookupStatusEnum.INVALID_OBSERVABLE,
        ProviderLookupStatusEnum.MALFORMED_RESPONSE,
        ProviderLookupStatusEnum.FAILED,
    }
)


def _resolve_verdict_conservatively(
    results: List[ObservableLookupResult],
) -> Tuple[ObservableVerdictEnum, Optional[float], Optional[str]]:
    """
    Resolve multiple provider lookup results into a conservative verdict.
    - No FOUND results -> UNKNOWN, None
    - Conflicting BENIGN vs MALICIOUS -> downgraded to UNKNOWN with conflict warning
    - Consistent FOUND verdict -> explicit provider verdict + highest supplied confidence (if any)
    """
    found = [r for r in results if r.lookup_status == ProviderLookupStatusEnum.FOUND]
    if not found:
        return ObservableVerdictEnum.UNKNOWN, None, None

    verdicts = {r.verdict for r in found}
    if (
        (ObservableTypeEnum and False)
        or (
            ObservableVerdictEnum.MALICIOUS in verdicts
            and ObservableVerdictEnum.BENIGN in verdicts
        )
        or (
            ObservableVerdictEnum.SUSPICIOUS in verdicts
            and ObservableVerdictEnum.BENIGN in verdicts
        )
    ):
        return (
            ObservableVerdictEnum.UNKNOWN,
            None,
            "Conflicting provider verdicts (malicious vs benign); resolved conservatively to 'unknown'",
        )

    if ObservableVerdictEnum.MALICIOUS in verdicts:
        chosen = ObservableVerdictEnum.MALICIOUS
    elif ObservableVerdictEnum.SUSPICIOUS in verdicts:
        chosen = ObservableVerdictEnum.SUSPICIOUS
    elif ObservableVerdictEnum.BENIGN in verdicts:
        chosen = ObservableVerdictEnum.BENIGN
    else:
        chosen = ObservableVerdictEnum.UNKNOWN

    confidences = [r.confidence for r in found if r.verdict == chosen and r.confidence is not None]
    chosen_conf = max(confidences) if confidences else None
    return chosen, chosen_conf, None


class ThreatIntelObservablePipeline:
    """
    Coordinates Day 9 observable enrichment with Day 10 provider-neutral TI lookups.
    Never mutates input normalized events or raw evidence.
    """

    def __init__(
        self,
        *,
        base_enricher: Optional[DeterministicEventEnricher] = None,
        ti_providers: Optional[Sequence[ThreatIntelProviderProtocol]] = None,
        retry_policy: Optional[RetryPolicy] = None,
        circuit_breaker: Optional[ProviderCircuitBreaker] = None,
        disabled_providers: Optional[Sequence[str]] = None,
    ) -> None:
        self._base_enricher = base_enricher or DeterministicEventEnricher()
        self._ti_providers: List[ThreatIntelProviderProtocol] = (
            list(ti_providers) if ti_providers is not None else [FixtureThreatIntelProvider()]
        )
        self._retry_policy = retry_policy or RetryPolicy(max_attempts=1)
        self._circuit_breaker = circuit_breaker or ProviderCircuitBreaker()
        self._disabled_providers = {p.strip().lower() for p in (disabled_providers or ()) if p and p.strip()}

    @property
    def circuit_breaker(self) -> ProviderCircuitBreaker:
        return self._circuit_breaker

    def lookup_observable(
        self,
        observable_type: Any,
        value: Any,
        *,
        lookup_timestamp: Optional[str] = None,
    ) -> List[ObservableLookupResult]:
        """
        Validate a single observable before querying all configured TI providers
        using unified retry, circuit-breaker, and safe-request enforcement.
        """
        ts = lookup_timestamp or utc_now_iso()
        is_valid, request, err_msg, is_unsupported_type = validate_safe_provider_request(
            observable_type, value
        )
        if not is_valid or request is None:
            provider_name = (
                self._ti_providers[0].provider_name
                if self._ti_providers
                else "autosoc.validation"
            )
            provider_ver = (
                self._ti_providers[0].provider_version if self._ti_providers else "0.1.0"
            )
            return [
                ObservableLookupResult(
                    provider_name=provider_name,
                    provider_version=provider_ver,
                    observable_type=ObservableTypeEnum.IP,
                    normalized_value="",
                    lookup_status=ProviderLookupStatusEnum.UNSUPPORTED_OBSERVABLE
                    if is_unsupported_type
                    else ProviderLookupStatusEnum.INVALID_OBSERVABLE,
                    verdict=ObservableVerdictEnum.UNKNOWN,
                    confidence=None,
                    evidence={},
                    references=[],
                    lookup_timestamp=ts,
                    errors=[
                        ValidationIssue(
                            category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE
                            if is_unsupported_type
                            else ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                            field="observable_type" if is_unsupported_type else "normalized_value",
                            message=err_msg or "Rejected invalid observable pre-lookup",
                            severity="error",
                        )
                    ],
                    live_lookup_performed=False,
                )
            ]

        results: List[ObservableLookupResult] = []
        for provider in self._ti_providers:
            prov_enabled = (
                provider.provider_name.strip().lower() not in self._disabled_providers
                and bool(getattr(provider, "is_enabled", True))
            )
            res = execute_lookup_with_reliability(
                provider_name=provider.provider_name,
                provider_version=provider.provider_version,
                is_live_lookup=provider.is_live_lookup,
                enabled=prov_enabled,
                supported_types=provider.supported_observable_types,
                request=request,
                call_fn=lambda req, call_ts, p=provider: p.lookup(req, lookup_timestamp=call_ts),
                retry_policy=self._retry_policy,
                circuit_breaker=self._circuit_breaker,
                lookup_timestamp=ts,
            )
            results.append(res)
        return results

    def enrich_with_threat_intel(
        self, event: Any, *, enriched_at: Optional[str] = None
    ) -> EventEnrichmentResult:
        """
        Enrich a normalized event with Day 9 deterministic context + Day 10 TI provider lookups.
        Deduplicated observables are queried once per unique (type, normalized_value).
        Partial results are preserved when individual lookups fail.
        """
        ts = enriched_at or utc_now_iso()
        base_result = self._base_enricher.enrich_event(event, enriched_at=ts)

        if base_result.enrichment_status in (
            EnrichmentStatusEnum.FAILED,
            EnrichmentStatusEnum.SKIPPED,
            EnrichmentStatusEnum.NO_OBSERVABLES,
        ) and base_result.observable_count == 0:
            return base_result

        warnings: List[ValidationIssue] = list(base_result.warnings)
        updated_observables: List[EnrichedObservable] = []
        any_live_lookup = bool(base_result.live_lookup_performed)
        any_provider_failure = False

        for obs in base_result.observables:
            ti_results = self.lookup_observable(
                obs.observable_type, obs.normalized_value, lookup_timestamp=ts
            )

            for ti_res in ti_results:
                if ti_res.live_lookup_performed:
                    any_live_lookup = True
                if ti_res.lookup_status in _FAILURE_STATUSES:
                    any_provider_failure = True
                    msg = (
                        ti_res.errors[0].message
                        if ti_res.errors
                        else f"TI lookup failed with status '{ti_res.lookup_status.value}'"
                    )
                    warnings.append(
                        ValidationIssue(
                            category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                            field=f"threat_intel.{ti_res.provider_name}",
                            message=f"{obs.observable_type.value} lookup ({ti_res.lookup_status.value}): {msg}",
                            severity="warning",
                        )
                    )
                elif ti_res.lookup_status == ProviderLookupStatusEnum.UNSUPPORTED_OBSERVABLE:
                    warnings.append(
                        ValidationIssue(
                            category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
                            field=f"threat_intel.{ti_res.provider_name}",
                            message=f"Provider '{ti_res.provider_name}' does not support '{obs.observable_type.value}'",
                            severity="warning",
                        )
                    )

            resolved_verdict, resolved_conf, conflict_msg = _resolve_verdict_conservatively(
                ti_results
            )
            if conflict_msg:
                warnings.append(
                    ValidationIssue(
                        category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                        field="threat_intel.verdict",
                        message=conflict_msg,
                        severity="warning",
                    )
                )

            new_context = dict(obs.context)
            new_context["threat_intel"] = {
                "verdict": resolved_verdict.value,
                "confidence": resolved_conf,
                "live_lookup_performed": any(r.live_lookup_performed for r in ti_results),
                "lookups": [
                    {
                        "provider_name": r.provider_name,
                        "provider_version": r.provider_version,
                        "lookup_status": r.lookup_status.value,
                        "verdict": r.verdict.value,
                        "confidence": r.confidence,
                        "evidence": r.evidence,
                        "references": [ref.model_dump() for ref in r.references],
                        "lookup_timestamp": r.lookup_timestamp,
                        "live_lookup_performed": r.live_lookup_performed,
                    }
                    for r in ti_results
                ],
            }

            updated_prov = obs.provenance
            # Preserve all Day 9 source_fields / original_values provenance and update live flag
            prov_dump = updated_prov.model_dump()
            prov_dump["live_lookup_performed"] = any(
                r.live_lookup_performed for r in ti_results
            )
            prov_dump["provider"] = (
                f"{updated_prov.provider}+ti[{','.join(p.provider_name for p in self._ti_providers)}]"
                if self._ti_providers
                else updated_prov.provider
            )

            from app.threat_intelligence.schemas import EnrichmentProvenance

            updated_observables.append(
                EnrichedObservable(
                    observable_type=obs.observable_type,
                    normalized_value=obs.normalized_value,
                    original_value=obs.original_value,
                    classification=obs.classification,
                    verdict=resolved_verdict,
                    context=new_context,
                    provenance=EnrichmentProvenance(**prov_dump),
                )
            )

        status = (
            EnrichmentStatusEnum.ENRICHED_PARTIAL
            if (warnings or any_provider_failure)
            else EnrichmentStatusEnum.ENRICHED
        )

        return EventEnrichmentResult(
            enrichment_status=status,
            source_event_id=base_result.source_event_id,
            ingestion_id=base_result.ingestion_id,
            enriched_at=ts,
            provider=base_result.provider,
            provider_version=base_result.provider_version,
            live_lookup_performed=any_live_lookup,
            observable_count=len(updated_observables),
            observables=updated_observables,
            warnings=warnings,
            errors=base_result.errors,
        )
