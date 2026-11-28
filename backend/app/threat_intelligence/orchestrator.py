"""
AutoSOC - Threat Intelligence Provider Orchestrator (Day 10)

Coordinates configured external Threat Intelligence providers on top of Day 9's
deterministic local enrichment while enforcing:
  - Offline deterministic fallback when TI is disabled or unconfigured
  - Per-event maximum observable lookup caps
  - Strict timeout enforcement (asyncio.wait_for) without blocking ingestion
  - Two-tier TTL cache + single-flight request coalescing
  - Untrusted external response validation (rejecting malformed / raw-leak / unsubstantiated malicious verdicts)
  - Conservative verdict aggregation and secret redaction
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Sequence

import httpx
from pydantic import BaseModel, Field, ValidationError

from app.core.config import settings
from app.events.validation import ValidationErrorCategory, ValidationIssue
from app.threat_intelligence.cache import ThreatIntelCache
from app.threat_intelligence.providers import (
    ThreatIntelProviderProtocol,
    ThreatIntelProviderUnavailableError,
    build_configured_ti_providers,
    scrub_secrets,
)
from app.threat_intelligence.schemas import (
    EnrichedObservable,
    ObservableTypeEnum,
    ObservableVerdictEnum,
    ThreatIntelLookupRequest,
    ThreatIntelLookupResult,
    ThreatIntelLookupStatusEnum,
    contains_forbidden_ti_keys,
)

logger = logging.getLogger("autosoc")

_VERDICT_PRIORITY: Dict[ObservableVerdictEnum, int] = {
    ObservableVerdictEnum.MALICIOUS: 4,
    ObservableVerdictEnum.SUSPICIOUS: 3,
    ObservableVerdictEnum.BENIGN: 2,
    ObservableVerdictEnum.UNKNOWN: 1,
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ThreatIntelOrchestrationOutcome(BaseModel):
    """Result returned by ThreatIntelOrchestrator back into DeterministicEventEnricher."""

    observables: List[EnrichedObservable] = Field(default_factory=list)
    live_lookup_performed: bool = False
    providers_queried: List[str] = Field(default_factory=list)
    cache_hits: int = 0
    live_lookups: int = 0
    threat_intel_context: Optional[Dict[str, Any]] = None
    warnings: List[ValidationIssue] = Field(default_factory=list)
    has_partial_failures: bool = False


class ThreatIntelOrchestrator:
    """
    Executes configured external TI providers deterministically, safely, and
    non-blockingly across deduplicated observables extracted by Day 9 enrichment.
    """

    def __init__(
        self,
        *,
        enabled: Optional[bool] = None,
        provider_names: Optional[Sequence[str]] = None,
        timeout_seconds: Optional[float] = None,
        max_observables_per_event: Optional[int] = None,
        cache: Optional[ThreatIntelCache] = None,
        providers: Optional[Dict[str, ThreatIntelProviderProtocol]] = None,
        settings_obj: Any = settings,
    ) -> None:
        self._settings = settings_obj
        self._explicit_enabled = enabled
        self._explicit_provider_names = (
            [p.strip().lower() for p in provider_names if p and p.strip()]
            if provider_names is not None
            else None
        )
        self._explicit_timeout = timeout_seconds
        self._explicit_max_observables = max_observables_per_event
        self._explicit_providers = providers

        self._cache = cache or ThreatIntelCache(
            ttl_seconds=int(getattr(settings_obj, "TI_CACHE_TTL_SECONDS", 300)),
            use_redis=bool(getattr(settings_obj, "TI_USE_REDIS_CACHE", True)),
        )

    @property
    def enabled(self) -> bool:
        if self._explicit_enabled is not None:
            return bool(self._explicit_enabled)
        return bool(getattr(self._settings, "TI_ENABLED", False))

    @property
    def timeout_seconds(self) -> float:
        if self._explicit_timeout is not None:
            return float(self._explicit_timeout)
        return float(getattr(self._settings, "TI_TIMEOUT_SECONDS", 3.0))

    @property
    def max_observables_per_event(self) -> int:
        if self._explicit_max_observables is not None:
            return int(self._explicit_max_observables)
        return int(getattr(self._settings, "TI_MAX_OBSERVABLES_PER_EVENT", 10))

    @property
    def cache(self) -> ThreatIntelCache:
        return self._cache

    def _collect_secrets(self) -> List[str]:
        secrets: List[str] = []
        for attr in (
            "TI_VIRUSTOTAL_API_KEY",
            "TI_ABUSEIPDB_API_KEY",
            "TI_OTX_API_KEY",
            "TI_GENERIC_API_KEY",
        ):
            val = getattr(self._settings, attr, None)
            if val is not None:
                raw = val.get_secret_value() if hasattr(val, "get_secret_value") else str(val)
                if raw and raw.strip():
                    secrets.append(raw.strip())
        if self._explicit_providers:
            for prov in self._explicit_providers.values():
                getter = getattr(prov, "secret_values", None)
                if callable(getter):
                    secrets.extend(getter())
        return secrets

    def _resolve_requested_provider_names(self) -> List[str]:
        if self._explicit_provider_names is not None:
            return list(dict.fromkeys(self._explicit_provider_names))
        if hasattr(self._settings, "enabled_ti_providers"):
            if self.enabled and getattr(self._settings, "TI_PROVIDERS", ""):
                return [
                    p.strip().lower()
                    for p in str(self._settings.TI_PROVIDERS).split(",")
                    if p.strip()
                ]
            return []
        return []

    def _resolve_provider_registry(self) -> Dict[str, ThreatIntelProviderProtocol]:
        if self._explicit_providers is not None:
            return self._explicit_providers
        return build_configured_ti_providers(self._settings)

    def resolve_active_providers(self) -> tuple[List[ThreatIntelProviderProtocol], List[ValidationIssue]]:
        """
        Return configured, ready providers for this orchestrator along with
        non-blocking warnings for requested providers that are missing/unconfigured.
        """
        if not self.enabled:
            return [], []

        requested = self._resolve_requested_provider_names()
        registry = self._resolve_provider_registry()
        active: List[ThreatIntelProviderProtocol] = []
        warnings: List[ValidationIssue] = []

        # If TI_ENABLED=True with no TI_PROVIDERS list, auto-select configured registry entries
        if not requested and self._explicit_providers is not None:
            requested = list(registry.keys())

        for name in requested:
            provider = registry.get(name)
            if provider is None:
                warnings.append(
                    ValidationIssue(
                        category=ValidationErrorCategory.UNSUPPORTED_SOURCE_TYPE,
                        field=f"ti.provider.{name}",
                        message=f"Configured TI provider '{name}' is unknown; skipped",
                        severity="warning",
                    )
                )
                continue
            if not provider.is_configured():
                warnings.append(
                    ValidationIssue(
                        category=ValidationErrorCategory.MISSING_REQUIRED_FIELD,
                        field=f"ti.provider.{name}",
                        message=f"TI provider '{name}' is enabled but missing credentials/configuration",
                        severity="warning",
                    )
                )
                continue
            active.append(provider)

        return active, warnings

    async def _execute_single_provider_lookup(
        self,
        provider: ThreatIntelProviderProtocol,
        request: ThreatIntelLookupRequest,
        secrets: Sequence[str],
    ) -> ThreatIntelLookupResult:
        async def _call_and_validate() -> ThreatIntelLookupResult:
            try:
                raw_output = await asyncio.wait_for(
                    provider.lookup(request),
                    timeout=request.timeout_seconds,
                )
            except asyncio.TimeoutError:
                return ThreatIntelLookupResult(
                    provider=provider.provider_id,
                    provider_version=provider.provider_version,
                    observable_type=request.observable_type,
                    normalized_value=request.normalized_value,
                    lookup_status=ThreatIntelLookupStatusEnum.TIMEOUT,
                    verdict=ObservableVerdictEnum.UNKNOWN,
                    evidence=f"TI provider '{provider.provider_id}' timed out after {request.timeout_seconds:.1f}s",
                    lookup_timestamp=_utc_now_iso(),
                    live_lookup_performed=False,
                    error_message=f"Provider '{provider.provider_id}' lookup timeout",
                )
            except (ThreatIntelProviderUnavailableError, httpx.HTTPError, ConnectionError, OSError) as exc:
                safe_msg = scrub_secrets(str(exc), secrets) or type(exc).__name__
                return ThreatIntelLookupResult(
                    provider=provider.provider_id,
                    provider_version=provider.provider_version,
                    observable_type=request.observable_type,
                    normalized_value=request.normalized_value,
                    lookup_status=ThreatIntelLookupStatusEnum.UNAVAILABLE,
                    verdict=ObservableVerdictEnum.UNKNOWN,
                    evidence=f"TI provider '{provider.provider_id}' unavailable",
                    lookup_timestamp=_utc_now_iso(),
                    live_lookup_performed=False,
                    error_message=f"{provider.provider_id} unavailable: {safe_msg}"[:256],
                )
            except Exception as exc:
                safe_msg = scrub_secrets(type(exc).__name__, secrets)
                return ThreatIntelLookupResult(
                    provider=provider.provider_id,
                    provider_version=provider.provider_version,
                    observable_type=request.observable_type,
                    normalized_value=request.normalized_value,
                    lookup_status=ThreatIntelLookupStatusEnum.INVALID_RESPONSE,
                    verdict=ObservableVerdictEnum.UNKNOWN,
                    evidence=f"TI provider '{provider.provider_id}' failed with {safe_msg}",
                    lookup_timestamp=_utc_now_iso(),
                    live_lookup_performed=False,
                    error_message=f"{provider.provider_id} error: {safe_msg}"[:256],
                )

            if not isinstance(raw_output, dict) or contains_forbidden_ti_keys(raw_output):
                return ThreatIntelLookupResult(
                    provider=provider.provider_id,
                    provider_version=provider.provider_version,
                    observable_type=request.observable_type,
                    normalized_value=request.normalized_value,
                    lookup_status=ThreatIntelLookupStatusEnum.INVALID_RESPONSE,
                    verdict=ObservableVerdictEnum.UNKNOWN,
                    evidence="Rejected untrusted TI provider response (invalid structure or forbidden raw key)",
                    lookup_timestamp=_utc_now_iso(),
                    live_lookup_performed=False,
                    error_message=f"{provider.provider_id} returned malformed or unsafe response",
                )

            candidate = dict(raw_output)
            candidate.setdefault("provider", provider.provider_id)
            candidate.setdefault("provider_version", provider.provider_version)
            candidate.setdefault("observable_type", request.observable_type.value)
            candidate.setdefault("normalized_value", request.normalized_value)
            candidate.setdefault("lookup_timestamp", _utc_now_iso())

            if isinstance(candidate.get("evidence"), str):
                candidate["evidence"] = scrub_secrets(candidate["evidence"], secrets)
            if isinstance(candidate.get("error_message"), str):
                candidate["error_message"] = scrub_secrets(candidate["error_message"], secrets)

            try:
                validated = ThreatIntelLookupResult(**candidate)
            except (ValidationError, ValueError, TypeError):
                return ThreatIntelLookupResult(
                    provider=provider.provider_id,
                    provider_version=provider.provider_version,
                    observable_type=request.observable_type,
                    normalized_value=request.normalized_value,
                    lookup_status=ThreatIntelLookupStatusEnum.INVALID_RESPONSE,
                    verdict=ObservableVerdictEnum.UNKNOWN,
                    evidence=f"TI provider '{provider.provider_id}' failed contract validation; verdict kept unknown",
                    lookup_timestamp=_utc_now_iso(),
                    live_lookup_performed=False,
                    error_message=f"{provider.provider_id} response failed strict TI schema validation",
                )

            if (
                validated.observable_type != request.observable_type
                or validated.normalized_value != request.normalized_value
            ):
                return ThreatIntelLookupResult(
                    provider=provider.provider_id,
                    provider_version=provider.provider_version,
                    observable_type=request.observable_type,
                    normalized_value=request.normalized_value,
                    lookup_status=ThreatIntelLookupStatusEnum.INVALID_RESPONSE,
                    verdict=ObservableVerdictEnum.UNKNOWN,
                    evidence="TI provider response observable mismatched request",
                    lookup_timestamp=_utc_now_iso(),
                    live_lookup_performed=False,
                    error_message=f"{provider.provider_id} returned mismatched observable identity",
                )

            return validated

        return await self._cache.get_or_fetch_singleflight(
            provider=provider.provider_id,
            observable_type=request.observable_type,
            normalized_value=request.normalized_value,
            fetcher=_call_and_validate,
        )

    @staticmethod
    def _select_consolidated_result(
        results: Sequence[ThreatIntelLookupResult],
    ) -> Optional[ThreatIntelLookupResult]:
        if not results:
            return None
        # Choose highest-severity trustworthy verdict; fall back to first success/no_data/failure
        trusted = [
            r
            for r in results
            if r.lookup_status in (ThreatIntelLookupStatusEnum.SUCCESS, ThreatIntelLookupStatusEnum.CACHE_HIT)
        ]
        if trusted:
            return max(
                trusted,
                key=lambda r: (
                    _VERDICT_PRIORITY.get(r.verdict, 0),
                    r.confidence if r.confidence is not None else -1.0,
                ),
            )
        for preferred_status in (
            ThreatIntelLookupStatusEnum.NO_DATA,
            ThreatIntelLookupStatusEnum.TIMEOUT,
            ThreatIntelLookupStatusEnum.UNAVAILABLE,
            ThreatIntelLookupStatusEnum.INVALID_RESPONSE,
        ):
            for r in results:
                if r.lookup_status == preferred_status:
                    return r
        return results[0]

    async def enrich_observables(
        self,
        observables: List[EnrichedObservable],
        *,
        ingestion_id: str,
        source_event_id: Optional[str] = None,
    ) -> ThreatIntelOrchestrationOutcome:
        """
        Execute configured external TI providers across deduplicated observables.
        When TI is disabled or no providers are active, preserves offline-only mode.
        """
        if not observables:
            return ThreatIntelOrchestrationOutcome(observables=[])

        active_providers, warnings = self.resolve_active_providers()
        secrets = self._collect_secrets()

        if not self.enabled or not active_providers:
            offline_obs = [
                obs.model_copy(
                    update={
                        "lookup_status": ThreatIntelLookupStatusEnum.OFFLINE_ONLY.value,
                        "provenance": obs.provenance.model_copy(
                            update={
                                "lookup_status": ThreatIntelLookupStatusEnum.OFFLINE_ONLY.value,
                            }
                        ),
                    }
                )
                for obs in observables
            ]
            return ThreatIntelOrchestrationOutcome(
                observables=offline_obs,
                live_lookup_performed=False,
                warnings=warnings,
                has_partial_failures=bool(warnings),
            )

        max_lookups = self.max_observables_per_event
        timeout = self.timeout_seconds
        updated_obs: List[EnrichedObservable] = []
        providers_queried: List[str] = []
        cache_hits = 0
        live_lookups = 0
        has_partial_failures = bool(warnings)

        ip_scores: List[int] = []
        ip_categories: List[str] = []
        domain_scores: List[int] = []
        hash_known_malware: Optional[bool] = None
        confidences: List[float] = []

        for idx, obs in enumerate(observables):
            if idx >= max_lookups:
                if idx == max_lookups:
                    warnings.append(
                        ValidationIssue(
                            category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                            field="ti.max_observables_per_event",
                            message=(
                                f"TI observable lookup cap ({max_lookups}) reached; "
                                "remaining observables kept offline"
                            ),
                            severity="warning",
                        )
                    )
                updated_obs.append(
                    obs.model_copy(
                        update={
                            "lookup_status": ThreatIntelLookupStatusEnum.SKIPPED_LIMIT.value,
                            "provenance": obs.provenance.model_copy(
                                update={
                                    "lookup_status": ThreatIntelLookupStatusEnum.SKIPPED_LIMIT.value,
                                }
                            ),
                        }
                    )
                )
                continue

            supporting = [p for p in active_providers if p.supports_observable(obs.observable_type)]
            if not supporting:
                updated_obs.append(
                    obs.model_copy(
                        update={
                            "lookup_status": ThreatIntelLookupStatusEnum.UNSUPPORTED.value,
                            "provenance": obs.provenance.model_copy(
                                update={
                                    "lookup_status": ThreatIntelLookupStatusEnum.UNSUPPORTED.value,
                                }
                            ),
                        }
                    )
                )
                continue

            req = ThreatIntelLookupRequest(
                observable_type=obs.observable_type,
                normalized_value=obs.normalized_value,
                source_event_id=source_event_id,
                ingestion_id=ingestion_id,
                timeout_seconds=timeout,
            )

            provider_results = await asyncio.gather(
                *(
                    self._execute_single_provider_lookup(prov, req, secrets)
                    for prov in supporting
                )
            )

            for r in provider_results:
                if r.provider not in providers_queried:
                    providers_queried.append(r.provider)
                if r.cache_hit:
                    cache_hits += 1
                elif r.live_lookup_performed:
                    live_lookups += 1

                if r.lookup_status in (
                    ThreatIntelLookupStatusEnum.TIMEOUT,
                    ThreatIntelLookupStatusEnum.UNAVAILABLE,
                    ThreatIntelLookupStatusEnum.INVALID_RESPONSE,
                ):
                    has_partial_failures = True
                    warnings.append(
                        ValidationIssue(
                            category=ValidationErrorCategory.INVALID_SCHEMA_TYPE,
                            field=f"ti.{r.provider}.{obs.observable_type.value}",
                            message=r.error_message
                            or f"TI provider '{r.provider}' returned status '{r.lookup_status.value}'",
                            severity="warning",
                        )
                    )

                if r.score is not None:
                    if obs.observable_type == ObservableTypeEnum.IP:
                        ip_scores.append(r.score)
                    elif obs.observable_type == ObservableTypeEnum.DOMAIN:
                        domain_scores.append(r.score)
                for cat in r.categories:
                    if obs.observable_type == ObservableTypeEnum.IP and cat not in ip_categories:
                        ip_categories.append(cat)
                if (
                    obs.observable_type == ObservableTypeEnum.FILE_HASH
                    and r.verdict == ObservableVerdictEnum.MALICIOUS
                ):
                    hash_known_malware = True
                if r.confidence is not None:
                    confidences.append(r.confidence)

            primary = self._select_consolidated_result(provider_results)
            if primary is None:
                updated_obs.append(obs)
                continue

            # Only allow trustworthy SUCCESS / CACHE_HIT verdicts to alter verdict
            resolved_verdict = (
                primary.verdict
                if primary.lookup_status
                in (ThreatIntelLookupStatusEnum.SUCCESS, ThreatIntelLookupStatusEnum.CACHE_HIT)
                else ObservableVerdictEnum.UNKNOWN
            )

            obs_context = dict(obs.context)
            obs_context["threat_intel"] = [
                {
                    "provider": r.provider,
                    "provider_version": r.provider_version,
                    "lookup_status": r.lookup_status.value,
                    "verdict": r.verdict.value,
                    "confidence": r.confidence,
                    "score": r.score,
                    "categories": list(r.categories),
                    "cache_hit": r.cache_hit,
                    "lookup_timestamp": r.lookup_timestamp,
                }
                for r in provider_results
            ]

            merged_evidence = obs.provenance.evidence
            if primary.evidence:
                merged_evidence = f"{obs.provenance.evidence}; TI: {primary.evidence}"[:512]

            any_live_for_obs = any(r.live_lookup_performed for r in provider_results)
            provenance_provider = (
                primary.provider
                if primary.lookup_status
                in (ThreatIntelLookupStatusEnum.SUCCESS, ThreatIntelLookupStatusEnum.CACHE_HIT)
                else obs.provenance.provider
            )
            provenance_version = (
                primary.provider_version
                if provenance_provider == primary.provider
                else obs.provenance.provider_version
            )

            updated_obs.append(
                obs.model_copy(
                    update={
                        "verdict": resolved_verdict,
                        "confidence": primary.confidence
                        if primary.lookup_status
                        in (
                            ThreatIntelLookupStatusEnum.SUCCESS,
                            ThreatIntelLookupStatusEnum.CACHE_HIT,
                        )
                        else None,
                        "lookup_status": primary.lookup_status.value,
                        "lookup_timestamp": primary.lookup_timestamp,
                        "context": obs_context,
                        "provenance": obs.provenance.model_copy(
                            update={
                                "provider": provenance_provider,
                                "provider_version": provenance_version,
                                "evidence": merged_evidence,
                                "live_lookup_performed": any_live_for_obs,
                                "lookup_status": primary.lookup_status.value,
                                "lookup_timestamp": primary.lookup_timestamp,
                            }
                        ),
                    }
                )
            )

        ti_context = (
            {
                "ip_score": max(ip_scores) if ip_scores else None,
                "ip_categories": ip_categories[:20],
                "domain_score": max(domain_scores) if domain_scores else None,
                "hash_known_malware": hash_known_malware,
                "sources": list(providers_queried),
                "providers_queried": list(providers_queried),
                "cache_hits": cache_hits,
                "live_lookups": live_lookups,
                "max_confidence": max(confidences) if confidences else None,
            }
            if providers_queried
            else None
        )

        return ThreatIntelOrchestrationOutcome(
            observables=updated_obs,
            live_lookup_performed=live_lookups > 0,
            providers_queried=providers_queried,
            cache_hits=cache_hits,
            live_lookups=live_lookups,
            threat_intel_context=ti_context,
            warnings=warnings,
            has_partial_failures=has_partial_failures,
        )
