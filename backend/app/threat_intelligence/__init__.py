"""
AutoSOC Threat Intelligence and Security Enrichment Package (Day 9, Day 10 & Day 11)

Exports the canonical enrichment contract, provider abstractions, deterministic
local enrichment engine, reliability/circuit-breaker/retry semantics, mock/fixture TI
adapter, and (when runtime HTTP/Pydantic deps are installed) external TI adapters,
TTL cache, and orchestrator.
"""

from app.threat_intelligence.enricher import DeterministicEventEnricher
from app.threat_intelligence.mock_adapter import (
    DEFAULT_SYNTHETIC_TI_FIXTURES,
    FixtureThreatIntelProvider,
)
from app.threat_intelligence.provider_contract import (
    ObservableLookupRequest,
    ObservableLookupResult,
    ProviderLookupStatusEnum,
    ProviderReference,
    ThreatIntelProviderProtocol,
    sanitize_provider_response,
    validate_observable_for_lookup,
)
from app.threat_intelligence.providers import (
    DeterministicLocalEnrichmentProvider,
    EnrichmentProviderProtocol,
    SyncTIProviderAdapter,
    ThreatIntelProviderProtocol as AsyncThreatIntelProviderProtocol,
    ThreatIntelProviderRateLimitedError,
    ThreatIntelProviderUnavailableError,
)
from app.threat_intelligence.reliability import (
    CircuitBreakerStateEnum,
    FORBIDDEN_OUTBOUND_REQUEST_KEYS,
    OPERATIONAL_FAILURE_STATUS_VALUES,
    ProviderCircuitBreaker,
    ProviderOperationalStateEnum,
    RETRYABLE_STATUS_VALUES,
    RetryPolicy,
    deduplicate_references,
    enforce_verdict_and_evidence_invariants,
    execute_lookup_with_reliability,
    validate_safe_provider_request,
)
from app.threat_intelligence.schemas import (
    EnrichedObservable,
    EnrichmentProvenance,
    EnrichmentStatusEnum,
    EventEnrichmentResult,
    ObservableClassificationEnum,
    ObservableTypeEnum,
    ObservableVerdictEnum,
    ThreatIntelLookupRequest,
    ThreatIntelLookupResult,
    ThreatIntelLookupStatusEnum,
)
from app.threat_intelligence.ti_adapter import ThreatIntelObservablePipeline

__all__ = [
    "AsyncThreatIntelProviderProtocol",
    "CircuitBreakerStateEnum",
    "DEFAULT_SYNTHETIC_TI_FIXTURES",
    "DeterministicEventEnricher",
    "DeterministicLocalEnrichmentProvider",
    "EnrichedObservable",
    "EnrichmentProvenance",
    "EnrichmentProviderProtocol",
    "EnrichmentStatusEnum",
    "EventEnrichmentResult",
    "FORBIDDEN_OUTBOUND_REQUEST_KEYS",
    "FixtureThreatIntelProvider",
    "OPERATIONAL_FAILURE_STATUS_VALUES",
    "ObservableClassificationEnum",
    "ObservableLookupRequest",
    "ObservableLookupResult",
    "ObservableTypeEnum",
    "ObservableVerdictEnum",
    "ProviderCircuitBreaker",
    "ProviderLookupStatusEnum",
    "ProviderOperationalStateEnum",
    "ProviderReference",
    "RETRYABLE_STATUS_VALUES",
    "RetryPolicy",
    "SyncTIProviderAdapter",
    "ThreatIntelLookupRequest",
    "ThreatIntelLookupResult",
    "ThreatIntelLookupStatusEnum",
    "ThreatIntelObservablePipeline",
    "ThreatIntelProviderProtocol",
    "ThreatIntelProviderRateLimitedError",
    "ThreatIntelProviderUnavailableError",
    "deduplicate_references",
    "enforce_verdict_and_evidence_invariants",
    "execute_lookup_with_reliability",
    "sanitize_provider_response",
    "validate_observable_for_lookup",
    "validate_safe_provider_request",
]

try:
    from app.threat_intelligence.cache import ThreatIntelCache, build_ti_cache_key
    from app.threat_intelligence.orchestrator import (
        ThreatIntelOrchestrationOutcome,
        ThreatIntelOrchestrator,
    )
    from app.threat_intelligence.providers import (
        AbuseIPDBProvider,
        GenericHTTPThreatIntelProvider,
        VirusTotalProvider,
        build_configured_ti_providers,
    )

    __all__.extend(
        [
            "AbuseIPDBProvider",
            "GenericHTTPThreatIntelProvider",
            "ThreatIntelCache",
            "ThreatIntelOrchestrationOutcome",
            "ThreatIntelOrchestrator",
            "VirusTotalProvider",
            "build_configured_ti_providers",
            "build_ti_cache_key",
        ]
    )
except ImportError:
    pass
