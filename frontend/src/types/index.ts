// ---------------------------------------------------------------------------
// AutoSOC – shared frontend types
// Single source of truth for all domain and system types.
// Do NOT define types in feature or component files — import from here.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// System and health types
// ---------------------------------------------------------------------------

/** Security severity levels used across the platform. */
export type SeverityLevel = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Status of a backend health/liveness check. */
export type HealthStatus = "loading" | "connected" | "unavailable";

/** Infrastructure readiness state for each known service. */
export interface InfrastructureReadiness {
  postgres: boolean;
  redis: boolean;
  qdrant: boolean;
  kafka: boolean;
}

/** Conceptual readiness state for the platform. */
export type ReadinessState = "ready" | "degraded" | "unavailable";

/** Raw readiness response from GET /ready – matches backend contract exactly. */
export interface ReadinessResponse {
  status: "ok" | "degraded" | string;
  postgres: boolean;
  redis: boolean;
  qdrant: boolean;
  kafka: boolean;
}

/** Structured readiness result returned by checkReadiness(). */
export interface ReadinessResult {
  state: ReadinessState;
  data?: ReadinessResponse;
  error?: unknown;
}

/** Health endpoint response shape (GET /health). */
export interface HealthCheckResponse {
  status: string;
  service: string;
}

/**
 * System information response shape (GET /api/v1/system/info).
 * Authoritative response contract from AutoSOC API v1 system endpoint.
 */
export interface SystemInfoResponse {
  project_name: string;
  version: string;
  api_version: string;
  environment: string;
}

/** Generic API response wrapper for future paginated or enveloped endpoints. */
export interface ApiResponse<T = unknown> {
  data: T;
  message?: string;
}

// ---------------------------------------------------------------------------
// Security Event Ingestion Contracts (Day 6)
// Aligned with backend/app/events/schemas.py & core/exceptions.py
// ---------------------------------------------------------------------------

/** Supported telemetry source systems (SourceTypeEnum). */
export type SecurityEventSource =
  | "sysmon"
  | "zeek"
  | "suricata"
  | "windows_event_log"
  | "auditd"
  | "osquery"
  | "custom";

/** Structured field validation error item returned by FastAPI 422 handler. */
export interface BackendValidationErrorItem {
  field?: string;
  message: string;
  type?: string;
}

/** Arbitrary JSON object payload submitted to the ingestion endpoint. */
export type EventIngestionRequest = Record<string, unknown>;

/** Response returned after submitting a security event for ingestion. */
export interface EventIngestionResponse {
  ingestion_id: string;
  event_id?: string | null;
  status: string;
  source?: string;
  event_type?: string;
  ingest_time?: string;
  timestamp?: string;
  message?: string;
}

/** Recent ingested event record returned by the retrieval endpoint. */
export interface IngestedEventRecord {
  ingestion_id: string;
  event_id?: string | null;
  source?: string;
  source_type?: string;
  event_type?: string;
  timestamp?: string;
  ingest_time?: string;
  status: string;
}

/** Envelope shapes supported by GET /api/v1/events. */
export interface RecentEventsEnvelope {
  events?: IngestedEventRecord[];
  items?: IngestedEventRecord[];
  total?: number;
}

// ---------------------------------------------------------------------------
// Generic async request state
// Used by useApiRequest hook for feature components.
// ---------------------------------------------------------------------------

/** Lifecycle state for an asynchronous data request. */
export type RequestStatus = "idle" | "loading" | "success" | "error";

/** Shaped state for any async request. */
export interface AsyncState<T> {
  status: RequestStatus;
  data: T | null;
  error: string | null;
}

// ---------------------------------------------------------------------------
// Security Domain Contracts
// These define the SHAPE of data the frontend expects from future endpoints.
// They are NOT connected to live APIs. No real data exists yet.
// ---------------------------------------------------------------------------

/** Alert lifecycle status values. */
export type AlertStatus = "open" | "investigating" | "resolved" | "false_positive";

/** Alert domain model — reflects planned backend Alert schema. */
export interface Alert {
  id: string;
  title: string;
  severity: SeverityLevel;
  status: AlertStatus;
  source: string;
  host: string;
  createdAt: string;
  mitreTactics?: string[];
  mitreTechniques?: string[];
}

/** Incident lifecycle status values. */
export type IncidentStatus = "open" | "triaged" | "contained" | "resolved" | "closed";

/** Incident domain model — reflects planned backend Incident schema. */
export interface Incident {
  id: string;
  title: string;
  severity: SeverityLevel;
  status: IncidentStatus;
  alertCount: number;
  assignedTo?: string;
  createdAt: string;
  updatedAt: string;
}

/** Investigation lifecycle status values. */
export type InvestigationStatus = "active" | "completed" | "archived";

/** Investigation domain model — reflects planned backend Investigation schema. */
export interface Investigation {
  id: string;
  title: string;
  incidentId?: string;
  status: InvestigationStatus;
  findingsCount: number;
  leadAnalyst?: string;
  createdAt: string;
}

/** Threat intelligence indicator type values. */
export type ThreatIndicatorType = "ip" | "domain" | "hash" | "url";

/** Threat intelligence indicator domain model. */
export interface ThreatIntelIndicator {
  id: string;
  type: ThreatIndicatorType;
  value: string;
  confidence: number;
  severity: SeverityLevel;
  source: string;
  tags: string[];
}

/** Threat hunting campaign status values. */
export type HuntingCampaignStatus = "draft" | "running" | "completed";

/** Threat hunting campaign domain model. */
export interface HuntingCampaign {
  id: string;
  name: string;
  query: string;
  status: HuntingCampaignStatus;
  findingsCount: number;
  createdAt: string;
}
