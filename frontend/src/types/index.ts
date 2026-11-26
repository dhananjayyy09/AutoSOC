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
  normalization_status?: NormalizationStatus | null;
  enrichment_status?: EnrichmentStatus | null;
  source?: string;
  source_type?: SecurityEventSource | string;
  possible_duplicate?: boolean;
  received_at?: string;
  warnings?: string[];
  event_type?: string;
  ingest_time?: string;
  timestamp?: string;
  message?: string;
}

/** Recent ingested event record returned by GET /api/v1/events/ingested. */
export interface IngestedEventRecord {
  ingestion_id: string;
  event_id?: string | null;
  source?: string;
  source_type?: SecurityEventSource | string;
  sensor_id?: string;
  event_type?: string;
  timestamp?: string;
  ingest_time?: string;
  raw_hash?: string;
  payload_size_bytes?: number;
  raw_payload_preview?: string;
  possible_duplicate?: boolean;
  received_at?: string;
  status: string;
}

/** Envelope shapes supported by GET /api/v1/events/ingested. */
export interface RecentEventsEnvelope {
  events?: IngestedEventRecord[];
  items?: IngestedEventRecord[];
  count?: number;
  limit?: number;
  total?: number;
}

// ---------------------------------------------------------------------------
// Normalized Security Event Contracts (Day 7)
// Aligned with backend/app/events/schemas.py & validation.py
// ---------------------------------------------------------------------------

/** High-level event category taxonomy (EventCategoryEnum). */
export type EventCategory =
  | "process"
  | "network"
  | "file"
  | "registry"
  | "auth"
  | "alert"
  | "unknown";

/** Normalized transport/application protocol (ProtocolEnum). */
export type EventProtocol =
  | "tcp"
  | "udp"
  | "icmp"
  | "dns"
  | "http"
  | "tls"
  | "smtp"
  | "ftp"
  | "ssh"
  | "rdp"
  | "smb"
  | "other";

/**
 * Known ingestion/normalization lifecycle statuses from backend contracts.
 * Unknown string values are also accepted for forward compatibility.
 */
export type PersistedNormalizationStatus =
  | "normalized"
  | "normalized_with_warnings"
  | "failed"
  | "unsupported";

export type NormalizationStatus =
  | "accepted"
  | "accepted_with_warnings"
  | "rejected"
  | PersistedNormalizationStatus
  | (string & {});

/** Allowlisted sort columns matching backend/app/events/query_contract.py. */
export type NormalizedEventSortField =
  | "created_at"
  | "timestamp"
  | "severity"
  | "source_type"
  | "event_category"
  | "normalization_status";

/**
 * Backend wire contract for GET /api/v1/events/normalized and /normalized/{event_id}.
 * Matches backend/app/events/api_schemas.py NormalizedEventResponse (omits raw payloads).
 */
export interface NormalizedEventResponse {
  event_id: string | null;
  ingestion_id: string;
  raw_envelope_id: number;
  timestamp: string | null;
  source_type: SecurityEventSource | string;
  sensor_id: string;
  event_category: EventCategory | string | null;
  event_type: string | null;
  host: string | null;
  user?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  protocol?: EventProtocol | string | null;
  process?: string | null;
  file_hash?: string | null;
  domain?: string | null;
  command_line?: string | null;
  severity?: number | null;
  metadata: Record<string, unknown>;
  normalization_status: NormalizationStatus;
  normalization_errors: string[];
  normalization_warnings: string[];
  enrichment_status?: string | null;
  enrichment?: EventEnrichmentContext | null;
  created_at: string;
}

/** Bounded list envelope returned by GET /api/v1/events/normalized. */
export interface NormalizedEventsEnvelope {
  items: NormalizedEventResponse[];
  count: number;
  limit: number;
  total?: number;
  offset?: number;
  has_more?: boolean;
}

/** Query parameters for the Normalized Event Explorer (Day 8). */
export interface NormalizedEventsQueryParams {
  limit?: number;
  offset?: number;
  search?: string;
  source_type?: SecurityEventSource | string;
  normalization_status?: PersistedNormalizationStatus | string;
  event_category?: EventCategory | string;
  event_type?: string;
  severity?: number;
  start_time?: string;
  end_time?: string;
  sort_by?: NormalizedEventSortField;
  sort_order?: "asc" | "desc";
}

/** Normalized result returned by queryNormalizedEvents(). */
export interface NormalizedEventListResult {
  items: NormalizedSecurityEvent[];
  count: number;
  limit: number;
  total?: number;
  offset?: number;
  has_more: boolean;
}

// ---------------------------------------------------------------------------
// Security Enrichment Context Contracts (Day 9 Reconciled)
// Canonical enrichment structures aligned with backend/app/events/enrichment_contract.py
// ---------------------------------------------------------------------------

/** Canonical enrichment status enum matching backend EnrichmentStatusEnum. */
export type CanonicalEnrichmentStatus =
  | "enriched"
  | "enriched_partial"
  | "no_observables"
  | "skipped"
  | "failed";

export type EnrichmentStatus =
  | CanonicalEnrichmentStatus
  | "partial"
  | "not_enriched"
  | (string & {});

/** Per-observable provenance metadata returned by canonical Day 9 enrichers. */
export interface ObservableProvenance {
  source_event_id?: string | null;
  ingestion_id?: string;
  source_fields?: string[];
  original_values?: string[];
  provider?: string;
  provider_version?: string;
  method?: string;
  evidence?: string;
  live_lookup_performed?: boolean;
}

/** Extracted observable and its deterministic enrichment context. */
export interface EventObservableEnrichment {
  observable: string;
  normalized_value?: string;
  original_value?: string | null;
  observable_type: string;
  classification?: string | null;
  verdict?: string | null;
  provider?: string | null;
  source_field?: string | null;
  enriched_at?: string | null;
  tags?: string[];
  provenance?: ObservableProvenance | string | null;
  context?: Record<string, unknown>;
}

/** Deterministic network & IP boundary context derived from normalized endpoints. */
export interface NetworkEnrichmentContext {
  is_internal_src?: boolean | null;
  is_internal_dst?: boolean | null;
  is_external_to_internal?: boolean | null;
  src_ip_version?: number | null;
  dst_ip_version?: number | null;
  dst_port_well_known?: boolean | null;
  geo?: Record<string, unknown> | null;
}

/** Deterministic structural attributes for domain, hash, and command indicators. */
export interface IndicatorEnrichmentContext {
  domain_length?: number | null;
  domain_tld?: string | null;
  subdomain_count?: number | null;
  has_file_hash?: boolean;
  file_hash_algorithm?: string | null;
  has_command_line?: boolean;
  command_line_length?: number | null;
}

/** Future threat-intel placeholder section (detection-neutral). */
export interface ThreatIntelContext {
  ip_score?: number | null;
  ip_categories?: string[];
  domain_score?: number | null;
  hash_known_malware?: boolean | null;
  sources?: string[];
}

/** Event-level enrichment context sections attached alongside observables[]. */
export interface EventEnrichmentContextSections {
  network?: NetworkEnrichmentContext;
  indicators?: IndicatorEnrichmentContext;
  threat_intel?: ThreatIntelContext | null;
}

/** Event-level enrichment provenance record. */
export interface EventEnrichmentProvenance {
  pipeline_version?: string;
  provider?: string;
  provider_version?: string;
  live_lookup_performed?: boolean;
  enriched_fields?: string[];
  source_event_id?: string;
  source_ingestion_id?: string;
}

/** Enrichment summary & derived context attached to a normalized event or /enrichment response. */
export interface EventEnrichmentContext {
  enrichment_id?: string | null;
  status?: EnrichmentStatus | null;
  provider?: string | null;
  provider_version?: string | null;
  live_lookup_performed?: boolean | null;
  observable_count?: number;
  enriched_at?: string | null;
  attempt_count?: number;
  observables?: EventObservableEnrichment[];
  context?: EventEnrichmentContextSections | null;
  provenance?: EventEnrichmentProvenance | null;
  warnings?: string[];
  errors?: string[];
  providers?: string[];
}

/**
 * Authoritative Normalized Security Event Model (v0.2.0).
 * Used across NormalizedEventView and tests (raw_event optional when omitted by safe API).
 */
export interface NormalizedSecurityEvent {
  // Core identification & classification fields (null when normalization failed/unsupported)
  event_id: string | null;
  ingestion_id: string;
  raw_envelope_id?: number;
  timestamp: string | null;
  source: SecurityEventSource | string;
  event_category: EventCategory | string | null;
  event_type: string | null;
  host: string | null;
  severity?: number | null;
  raw_event?: string;
  metadata: Record<string, unknown>;

  // Optional fields (null when absent)
  user?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  protocol?: EventProtocol | string | null;
  process?: string | null;
  file_hash?: string | null;
  domain?: string | null;
  command_line?: string | null;

  // Lifecycle metadata from retrieval endpoints
  normalization_status?: NormalizationStatus;
  sensor_id?: string | null;
  warnings?: string[];
  errors?: string[];
  enrichment_status?: string | null;
  enrichment?: EventEnrichmentContext | null;
  created_at?: string;
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
