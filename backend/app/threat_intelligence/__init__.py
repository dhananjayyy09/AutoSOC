"""
AutoSOC Threat Intelligence and Security Enrichment Package (Day 9 & Day 10)

Exports the canonical enrichment contract, provider abstractions, deterministic
local enricher, mock/fixture TI adapter, and observable lookup pipeline.
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
)
from app.threat_intelligence.schemas import (
    EnrichedObservable,
    EnrichmentProvenance,
    EnrichmentStatusEnum,
    EventEnrichmentResult,
    ObservableClassificationEnum,
    ObservableTypeEnum,
    ObservableVerdictEnum,
)
from app.threat_intelligence.ti_adapter import ThreatIntelObservablePipeline

__all__ = [
    "DEFAULT_SYNTHETIC_TI_FIXTURES",
    "DeterministicEventEnricher",
    "DeterministicLocalEnrichmentProvider",
    "EnrichedObservable",
    "EnrichmentProvenance",
    "EnrichmentProviderProtocol",
    "EnrichmentStatusEnum",
    "EventEnrichmentResult",
    "FixtureThreatIntelProvider",
    "ObservableClassificationEnum",
    "ObservableLookupRequest",
    "ObservableLookupResult",
    "ObservableTypeEnum",
    "ObservableVerdictEnum",
    "ProviderLookupStatusEnum",
    "ProviderReference",
    "ThreatIntelObservablePipeline",
    "ThreatIntelProviderProtocol",
    "sanitize_provider_response",
    "validate_observable_for_lookup",
]
