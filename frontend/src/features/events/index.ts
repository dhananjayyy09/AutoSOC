/**
 * Security Event Ingestion Feature Module (Day 6)
 */
export { EventIngestionForm } from "./event-ingestion-form";
export { RecentEventsList } from "./recent-events-list";
export {
  ingestSecurityEvent,
  fetchRecentEvents,
  EVENT_INGEST_ENDPOINT,
  EVENTS_LIST_ENDPOINT,
  DEFAULT_RECENT_EVENTS_LIMIT,
} from "@/lib/api";
export type {
  SecurityEventSource,
  EventIngestionRequest,
  EventIngestionResponse,
  IngestedEventRecord,
  RecentEventsEnvelope,
  BackendValidationErrorItem,
} from "@/types";

export const EVENTS_CONFIG = {
  title: "Event Ingestion",
  description: "Submit security event JSON payloads to the ingestion pipeline and inspect recent ingestion records.",
} as const;
