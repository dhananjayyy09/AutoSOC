/**
 * Security Event Ingestion, Normalization & Explorer Feature Module (Day 6–8)
 */
export { EventIngestionForm } from "./event-ingestion-form";
export { RecentEventsList } from "./recent-events-list";
export { NormalizationStatusBadge } from "./normalization-status-badge";
export { EnrichmentStatusBadge } from "./enrichment-status-badge";
export { ThreatLookupStatusBadge, ThreatVerdictBadge } from "./threat-intel-status-badge";
export { EnrichmentContextPanel } from "./enrichment-context-panel";
export { NormalizedEventView } from "./normalized-event-view";
export { NormalizedEventExplorer, getNormalizedEventKey } from "./normalized-event-explorer";
export {
  ingestSecurityEvent,
  fetchRecentEvents,
  fetchNormalizedEvents,
  queryNormalizedEvents,
  buildNormalizedEventsQueryString,
  fetchNormalizedEventById,
  fetchNormalizedEventEnrichment,
  retryNormalizedEventEnrichment,
  EVENT_INGEST_ENDPOINT,
  EVENTS_LIST_ENDPOINT,
  EVENTS_NORMALIZED_ENDPOINT,
  DEFAULT_RECENT_EVENTS_LIMIT,
  MAX_QUERY_LIMIT,
  MAX_QUERY_OFFSET,
} from "@/lib/api";
export type {
  SecurityEventSource,
  EventIngestionRequest,
  EventIngestionResponse,
  IngestedEventRecord,
  RecentEventsEnvelope,
  NormalizedEventResponse,
  NormalizedEventsEnvelope,
  NormalizedEventsQueryParams,
  NormalizedEventListResult,
  NormalizedEventSortField,
  PersistedNormalizationStatus,
  BackendValidationErrorItem,
  EventCategory,
  EventProtocol,
  NormalizationStatus,
  CanonicalEnrichmentStatus,
  EnrichmentStatus,
  ObservableProvenance,
  NetworkEnrichmentContext,
  IndicatorEnrichmentContext,
  ThreatIntelContext,
  EventEnrichmentContextSections,
  EventEnrichmentProvenance,
  NormalizedSecurityEvent,
  EventObservableEnrichment,
  EventEnrichmentContext,
  ThreatIntelLookupStatus,
} from "@/types";

export const EVENTS_CONFIG = {
  title: "Event Explorer & Ingestion",
  description: "Submit security event JSON payloads, search normalized events, and inspect raw vs. normalized records.",
} as const;
