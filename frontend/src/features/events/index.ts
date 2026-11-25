/**
 * Security Event Ingestion & Normalization Feature Module (Day 6–7)
 */
export { EventIngestionForm } from "./event-ingestion-form";
export { RecentEventsList } from "./recent-events-list";
export { NormalizationStatusBadge } from "./normalization-status-badge";
export { NormalizedEventView } from "./normalized-event-view";
export {
  ingestSecurityEvent,
  fetchRecentEvents,
  fetchNormalizedEvents,
  fetchNormalizedEventById,
  EVENT_INGEST_ENDPOINT,
  EVENTS_LIST_ENDPOINT,
  EVENTS_NORMALIZED_ENDPOINT,
  DEFAULT_RECENT_EVENTS_LIMIT,
} from "@/lib/api";
export type {
  SecurityEventSource,
  EventIngestionRequest,
  EventIngestionResponse,
  IngestedEventRecord,
  RecentEventsEnvelope,
  NormalizedEventResponse,
  NormalizedEventsEnvelope,
  BackendValidationErrorItem,
  EventCategory,
  EventProtocol,
  NormalizationStatus,
  NormalizedSecurityEvent,
} from "@/types";

export const EVENTS_CONFIG = {
  title: "Event Ingestion",
  description: "Submit security event JSON payloads to the ingestion pipeline and inspect raw and normalized event records.",
} as const;
