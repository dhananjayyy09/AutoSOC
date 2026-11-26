import type {
  BackendValidationErrorItem,
  EventEnrichmentContext,
  EventEnrichmentContextSections,
  EventEnrichmentProvenance,
  EventIngestionRequest,
  EventIngestionResponse,
  EventObservableEnrichment,
  HealthCheckResponse,
  IndicatorEnrichmentContext,
  IngestedEventRecord,
  NetworkEnrichmentContext,
  NormalizedEventListResult,
  NormalizedEventResponse,
  NormalizedEventsEnvelope,
  NormalizedEventsQueryParams,
  NormalizedSecurityEvent,
  ObservableProvenance,
  ReadinessResponse,
  ReadinessResult,
  RecentEventsEnvelope,
  SystemInfoResponse,
  ThreatIntelContext,
} from "@/types";

// ---------------------------------------------------------------------------
// Base URL resolution – strip trailing slash exactly once at startup
// ---------------------------------------------------------------------------
const getBaseUrl = (): string => {
  const envUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
  return envUrl.replace(/\/+$/, "");
};

export const API_BASE_URL = getBaseUrl();
const DEFAULT_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Error classification helpers
// ---------------------------------------------------------------------------

/** True when the error is from an AbortController timeout or manual abort. */
export function isAbortError(err: unknown): err is DOMException {
  return (
    err instanceof DOMException && err.name === "AbortError"
  );
}

/** True when the error is a network-level failure (no HTTP response received). */
export function isNetworkError(err: unknown): boolean {
  if (isAbortError(err)) return true;
  if (err instanceof TypeError && err.message.toLowerCase().includes("fetch")) return true;
  return false;
}

// ---------------------------------------------------------------------------
// ApiError — carries structured HTTP failure info
// ---------------------------------------------------------------------------
export class ApiError extends Error {
  readonly status: number;
  readonly statusText: string;
  readonly data?: unknown;

  constructor(status: number, statusText: string, data?: unknown) {
    super(`API Error: ${status} ${statusText}`);
    this.name = "ApiError";
    this.status = status;
    this.statusText = statusText;
    this.data = data;
  }

  /** User-visible message, never leaking raw internal server errors. */
  get userMessage(): string {
    if (this.status === 503) return "One or more backend services are currently unavailable.";
    if (this.status >= 500) return "The server encountered an unexpected error. Please try again later.";
    if (this.status === 422) return "The submitted payload failed validation. Please review your input and try again.";
    if (this.status === 409) return "Duplicate ingestion ID: an event envelope with this ingestion_id already exists.";
    if (this.status === 404) return "The requested endpoint or resource was not found.";
    if (this.status === 401 || this.status === 403) return "You do not have permission to perform this action.";
    return `Unexpected error (HTTP ${this.status}).`;
  }

  /** Extracts safe field-level validation errors from a 422 response, if present. */
  get validationErrors(): BackendValidationErrorItem[] {
    if (!this.data || typeof this.data !== "object") return [];
    const payload = this.data as Record<string, unknown>;
    if (!Array.isArray(payload.errors)) return [];
    return payload.errors
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === "object"))
      .map((item) => ({
        field: typeof item.field === "string" ? item.field : undefined,
        message: typeof item.message === "string" ? item.message : "Invalid value",
        type: typeof item.type === "string" ? item.type : undefined,
      }));
  }
}

// ---------------------------------------------------------------------------
// ApiClient — centralized HTTP dispatcher
// ---------------------------------------------------------------------------
export class ApiClient {
  /**
   * Core HTTP request dispatcher.
   * - Normalizes endpoints (adds leading slash if missing).
   * - Enforces a timeout using AbortController.
   * - Throws ApiError for non-2xx responses.
   * - Re-throws network/abort errors unmodified so callers can classify them.
   */
  static async request<T = unknown>(
    endpoint: string,
    options: RequestInit = {},
    timeoutMs = DEFAULT_TIMEOUT_MS
  ): Promise<T> {
    const baseUrl = getBaseUrl();
    const normalizedEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
    const url = `${baseUrl}${normalizedEndpoint}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    if (typeof timeoutId === "object" && typeof (timeoutId as unknown as { unref?: () => void }).unref === "function") {
      (timeoutId as unknown as { unref: () => void }).unref();
    }

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          ...options.headers,
        },
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        let errorData: unknown;
        try {
          errorData = await response.json();
        } catch {
          // Response body is empty or not JSON — that is fine
        }
        throw new ApiError(response.status, response.statusText, errorData);
      }

      return (await response.json()) as T;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  static async get<T = unknown>(
    endpoint: string,
    options: RequestInit = {},
    timeoutMs = DEFAULT_TIMEOUT_MS
  ): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: "GET" }, timeoutMs);
  }

  static async post<T = unknown>(
    endpoint: string,
    body?: unknown,
    options: RequestInit = {},
    timeoutMs = DEFAULT_TIMEOUT_MS
  ): Promise<T> {
    return this.request<T>(
      endpoint,
      {
        ...options,
        method: "POST",
        body: body !== undefined ? JSON.stringify(body) : undefined,
      },
      timeoutMs
    );
  }

  static async put<T = unknown>(
    endpoint: string,
    body?: unknown,
    options: RequestInit = {},
    timeoutMs = DEFAULT_TIMEOUT_MS
  ): Promise<T> {
    return this.request<T>(
      endpoint,
      {
        ...options,
        method: "PUT",
        body: body !== undefined ? JSON.stringify(body) : undefined,
      },
      timeoutMs
    );
  }

  static async delete<T = unknown>(
    endpoint: string,
    options: RequestInit = {},
    timeoutMs = DEFAULT_TIMEOUT_MS
  ): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: "DELETE" }, timeoutMs);
  }
}

// ---------------------------------------------------------------------------
// Domain-specific health/readiness helpers
// ---------------------------------------------------------------------------

/**
 * Checks application liveness via GET /health.
 * Returns 'connected' if the backend process is reachable, 'unavailable' otherwise.
 */
export const checkHealth = async (): Promise<{
  status: "connected" | "unavailable";
  data?: HealthCheckResponse;
  error?: unknown;
}> => {
  try {
    const res = await ApiClient.get<HealthCheckResponse>("/health", { cache: "no-store" });
    return { status: "connected", data: res };
  } catch (error) {
    return { status: "unavailable", error };
  }
};

/**
 * Checks infrastructure readiness via GET /ready.
 *
 * | HTTP status | Backend payload                | Frontend state |
 * |-------------|-------------------------------|----------------|
 * | 200         | all services true              | 'ready'        |
 * | 200         | any service false              | 'degraded'     |
 * | 503         | detail: { postgres, … }       | 'degraded'     |
 * | network err | –                              | 'unavailable'  |
 */
export const checkReadiness = async (): Promise<ReadinessResult> => {
  try {
    const res = await ApiClient.get<ReadinessResponse>("/ready", { cache: "no-store" });

    if (!res || typeof res !== "object") {
      return { state: "unavailable", error: new Error("Malformed /ready response") };
    }

    const isReady =
      res.status === "ok" &&
      res.postgres === true &&
      res.redis === true &&
      res.qdrant === true &&
      res.kafka === true;

    return {
      state: isReady ? "ready" : "degraded",
      data: {
        status: res.status ?? "ok",
        postgres: Boolean(res.postgres),
        redis: Boolean(res.redis),
        qdrant: Boolean(res.qdrant),
        kafka: Boolean(res.kafka),
      },
    };
  } catch (error) {
    // FastAPI raises HTTPException(503) with a 'detail' dict for degraded state
    if (error instanceof ApiError && error.status === 503) {
      const payload = error.data as Record<string, unknown> | undefined;
      const detail = (
        payload &&
        typeof payload === "object" &&
        "detail" in payload &&
        typeof payload.detail === "object" &&
        payload.detail !== null
          ? payload.detail
          : payload
      ) as Record<string, unknown> | undefined;

      if (detail && typeof detail === "object") {
        return {
          state: "degraded",
          data: {
            status: typeof detail.status === "string" ? detail.status : "degraded",
            postgres: Boolean(detail.postgres),
            redis: Boolean(detail.redis),
            qdrant: Boolean(detail.qdrant),
            kafka: Boolean(detail.kafka),
          },
          error,
        };
      }
      return { state: "degraded", error };
    }

    return { state: "unavailable", error };
  }
};

/**
 * Fetches system information via GET /api/v1/system/info.
 * Resolves to { status: "ok", data } when available, or { status: "unavailable", error } on error.
 */
export const checkSystemInfo = async (): Promise<{
  status: "ok" | "unavailable";
  data?: SystemInfoResponse;
  error?: unknown;
}> => {
  try {
    const res = await ApiClient.get<SystemInfoResponse>("/api/v1/system/info", { cache: "no-store" });
    return { status: "ok", data: res };
  } catch (error) {
    return { status: "unavailable", error };
  }
};

// ---------------------------------------------------------------------------
// Security Event Ingestion & Retrieval (Day 6)
// ---------------------------------------------------------------------------

export const EVENT_INGEST_ENDPOINT = "/api/v1/events/ingest";
export const EVENTS_LIST_ENDPOINT = "/api/v1/events/ingested";
export const EVENTS_NORMALIZED_ENDPOINT = "/api/v1/events/normalized";
export const DEFAULT_RECENT_EVENTS_LIMIT = 20;
export const MAX_QUERY_LIMIT = 100;
export const MAX_QUERY_OFFSET = 10_000;
export const MAX_SEARCH_LENGTH = 128;
export const MAX_EVENT_TYPE_LENGTH = 64;

/**
 * Submits a JSON security event payload to POST /api/v1/events/ingest.
 * Throws ApiError on HTTP 4xx/5xx or network/abort errors on transport failure.
 */
export const ingestSecurityEvent = async (
  payload: EventIngestionRequest
): Promise<EventIngestionResponse> => {
  const res = await ApiClient.post<EventIngestionResponse>(EVENT_INGEST_ENDPOINT, payload);
  if (!res || typeof res !== "object" || typeof res.ingestion_id !== "string") {
    throw new Error("Malformed response from event ingestion endpoint");
  }
  return res;
};

/**
 * Retrieves recent ingested events from GET /api/v1/events/ingested with bounded limit.
 * Normalizes array or enveloped ({ items } / { events }) responses without
 * fabricating missing records.
 */
export const fetchRecentEvents = async (
  limit = DEFAULT_RECENT_EVENTS_LIMIT
): Promise<IngestedEventRecord[]> => {
  const safeLimit = Math.max(1, Math.min(limit, 100));
  const res = await ApiClient.get<IngestedEventRecord[] | RecentEventsEnvelope>(
    `${EVENTS_LIST_ENDPOINT}?limit=${safeLimit}`,
    { cache: "no-store" }
  );

  let records: unknown[] = [];
  if (Array.isArray(res)) {
    records = res;
  } else if (res && typeof res === "object") {
    if (Array.isArray(res.events)) {
      records = res.events;
    } else if (Array.isArray(res.items)) {
      records = res.items;
    }
  }

  return records
    .filter((item): item is IngestedEventRecord => Boolean(item && typeof item === "object"))
    .slice(0, safeLimit);
};

function asStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((item): item is string => typeof item === "string");
}

function parseObservableProvenance(raw: unknown): ObservableProvenance | string | null {
  if (typeof raw === "string") return raw;
  if (!raw || typeof raw !== "object") return null;
  const p = raw as Record<string, unknown>;
  return {
    source_event_id: typeof p.source_event_id === "string" ? p.source_event_id : null,
    ingestion_id: typeof p.ingestion_id === "string" ? p.ingestion_id : undefined,
    source_fields: asStringArray(p.source_fields),
    original_values: asStringArray(p.original_values),
    provider: typeof p.provider === "string" ? p.provider : undefined,
    provider_version: typeof p.provider_version === "string" ? p.provider_version : undefined,
    method: typeof p.method === "string" ? p.method : undefined,
    evidence: typeof p.evidence === "string" ? p.evidence : undefined,
    live_lookup_performed:
      typeof p.live_lookup_performed === "boolean" ? p.live_lookup_performed : undefined,
  };
}

function parseEventEnrichmentSections(raw: unknown): EventEnrichmentContextSections | null {
  if (!raw || typeof raw !== "object") return null;
  const sec = raw as Record<string, unknown>;

  let network: NetworkEnrichmentContext | undefined;
  if (sec.network && typeof sec.network === "object") {
    const n = sec.network as Record<string, unknown>;
    network = {
      is_internal_src: typeof n.is_internal_src === "boolean" ? n.is_internal_src : null,
      is_internal_dst: typeof n.is_internal_dst === "boolean" ? n.is_internal_dst : null,
      is_external_to_internal:
        typeof n.is_external_to_internal === "boolean" ? n.is_external_to_internal : null,
      src_ip_version: typeof n.src_ip_version === "number" ? n.src_ip_version : null,
      dst_ip_version: typeof n.dst_ip_version === "number" ? n.dst_ip_version : null,
      dst_port_well_known:
        typeof n.dst_port_well_known === "boolean" ? n.dst_port_well_known : null,
      geo: n.geo && typeof n.geo === "object" ? (n.geo as Record<string, unknown>) : null,
    };
  }

  let indicators: IndicatorEnrichmentContext | undefined;
  if (sec.indicators && typeof sec.indicators === "object") {
    const ind = sec.indicators as Record<string, unknown>;
    indicators = {
      domain_length: typeof ind.domain_length === "number" ? ind.domain_length : null,
      domain_tld: typeof ind.domain_tld === "string" ? ind.domain_tld : null,
      subdomain_count: typeof ind.subdomain_count === "number" ? ind.subdomain_count : null,
      has_file_hash: typeof ind.has_file_hash === "boolean" ? ind.has_file_hash : undefined,
      file_hash_algorithm:
        typeof ind.file_hash_algorithm === "string" ? ind.file_hash_algorithm : null,
      has_command_line:
        typeof ind.has_command_line === "boolean" ? ind.has_command_line : undefined,
      command_line_length:
        typeof ind.command_line_length === "number" ? ind.command_line_length : null,
    };
  }

  let threatIntel: ThreatIntelContext | null | undefined;
  if (sec.threat_intel && typeof sec.threat_intel === "object") {
    const ti = sec.threat_intel as Record<string, unknown>;
    threatIntel = {
      ip_score: typeof ti.ip_score === "number" ? ti.ip_score : null,
      ip_categories: asStringArray(ti.ip_categories),
      domain_score: typeof ti.domain_score === "number" ? ti.domain_score : null,
      hash_known_malware:
        typeof ti.hash_known_malware === "boolean" ? ti.hash_known_malware : null,
      sources: asStringArray(ti.sources),
    };
  }

  if (!network && !indicators && !threatIntel) return null;
  return { network, indicators, threat_intel: threatIntel ?? null };
}

function parseEventEnrichmentProvenance(raw: unknown): EventEnrichmentProvenance | null {
  if (!raw || typeof raw !== "object") return null;
  const p = raw as Record<string, unknown>;
  return {
    pipeline_version: typeof p.pipeline_version === "string" ? p.pipeline_version : undefined,
    provider: typeof p.provider === "string" ? p.provider : undefined,
    provider_version: typeof p.provider_version === "string" ? p.provider_version : undefined,
    live_lookup_performed:
      typeof p.live_lookup_performed === "boolean" ? p.live_lookup_performed : undefined,
    enriched_fields: asStringArray(p.enriched_fields),
    source_event_id: typeof p.source_event_id === "string" ? p.source_event_id : undefined,
    source_ingestion_id:
      typeof p.source_ingestion_id === "string" ? p.source_ingestion_id : undefined,
  };
}

/**
 * Safely extracts canonical EventEnrichmentContext from top-level `res.enrichment`,
 * `/enrichment` responses, or `res.metadata.enrichment` without inventing verdicts.
 */
function normalizeEnrichmentContext(
  rawEnrichment: unknown,
  fallbackStatus?: string | null
): EventEnrichmentContext | null {
  if (!rawEnrichment || typeof rawEnrichment !== "object") {
    if (typeof fallbackStatus === "string" && fallbackStatus.trim()) {
      return { status: fallbackStatus };
    }
    return null;
  }

  const obj = rawEnrichment as Record<string, unknown>;
  const nestedData =
    obj.enrichment_data && typeof obj.enrichment_data === "object"
      ? (obj.enrichment_data as Record<string, unknown>)
      : null;

  const parentEnrichedAt = typeof obj.enriched_at === "string" ? obj.enriched_at : null;
  const rawObservables = Array.isArray(obj.observables)
    ? obj.observables
    : Array.isArray(nestedData?.observables)
      ? nestedData.observables
      : null;

  const observables: EventObservableEnrichment[] = rawObservables
    ? rawObservables
        .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === "object"))
        .map((item) => {
          const parsedProv = parseObservableProvenance(item.provenance);
          const provObj =
            parsedProv && typeof parsedProv === "object" ? parsedProv : null;
          const normalizedValue =
            typeof item.normalized_value === "string" ? item.normalized_value : undefined;
          const originalValue =
            typeof item.original_value === "string" ? item.original_value : null;
          const observableValue =
            typeof item.observable === "string"
              ? item.observable
              : normalizedValue ??
                originalValue ??
                (typeof item.value === "string" ? item.value : "");
          const sourceField =
            typeof item.source_field === "string"
              ? item.source_field
              : provObj?.source_fields && provObj.source_fields.length > 0
                ? provObj.source_fields.join(", ")
                : typeof parsedProv === "string"
                  ? parsedProv
                  : null;
          const providerName =
            typeof item.provider === "string"
              ? item.provider
              : provObj?.provider ??
                (typeof item.source === "string" ? item.source : null);

          return {
            observable: observableValue,
            normalized_value: normalizedValue,
            original_value: originalValue,
            observable_type:
              typeof item.observable_type === "string"
                ? item.observable_type
                : typeof item.type === "string"
                  ? item.type
                  : "unknown",
            classification:
              typeof item.classification === "string"
                ? item.classification
                : typeof item.context === "string"
                  ? item.context
                  : typeof item.verdict === "string"
                    ? item.verdict
                    : null,
            verdict: typeof item.verdict === "string" ? item.verdict : null,
            provider: providerName,
            source_field: sourceField,
            enriched_at:
              typeof item.enriched_at === "string"
                ? item.enriched_at
                : typeof item.timestamp === "string"
                  ? item.timestamp
                  : parentEnrichedAt,
            tags: asStringArray(item.tags),
            provenance: parsedProv,
            context:
              item.context && typeof item.context === "object"
                ? (item.context as Record<string, unknown>)
                : undefined,
          };
        })
        .filter((item) => item.observable.length > 0)
    : [];

  const resolvedStatus =
    typeof obj.enrichment_status === "string"
      ? obj.enrichment_status
      : typeof obj.status === "string"
        ? obj.status
        : (fallbackStatus ?? null);

  const provenance = parseEventEnrichmentProvenance(obj.provenance);
  const provider =
    typeof obj.provider === "string"
      ? obj.provider
      : provenance?.provider ?? null;
  const providerVersion =
    typeof obj.provider_version === "string"
      ? obj.provider_version
      : provenance?.provider_version ?? null;
  const liveLookupPerformed =
    typeof obj.live_lookup_performed === "boolean"
      ? obj.live_lookup_performed
      : typeof provenance?.live_lookup_performed === "boolean"
        ? provenance.live_lookup_performed
        : null;

  const providersList =
    asStringArray(obj.providers) ?? (provider ? [provider] : undefined);

  return {
    enrichment_id: typeof obj.enrichment_id === "string" ? obj.enrichment_id : null,
    status: resolvedStatus,
    provider,
    provider_version: providerVersion,
    live_lookup_performed: liveLookupPerformed,
    observable_count:
      typeof obj.observable_count === "number" ? obj.observable_count : observables.length,
    enriched_at: parentEnrichedAt,
    attempt_count:
      typeof obj.attempt_count === "number" ? obj.attempt_count : undefined,
    observables,
    context: parseEventEnrichmentSections(obj.context ?? nestedData?.context),
    provenance,
    warnings: asStringArray(obj.warnings) ?? [],
    errors: asStringArray(obj.errors) ?? [],
    providers: providersList,
  };
}

/**
 * Maps backend NormalizedEventResponse wire format to NormalizedSecurityEvent.
 */
export function mapNormalizedEventResponse(
  res: NormalizedEventResponse
): NormalizedSecurityEvent {
  const safeMetadata = res.metadata && typeof res.metadata === "object" ? res.metadata : {};
  const rawEnrichment =
    res.enrichment ?? (safeMetadata.enrichment as unknown) ?? null;
  const rawEnrichmentObj =
    rawEnrichment && typeof rawEnrichment === "object"
      ? (rawEnrichment as Record<string, unknown>)
      : null;
  const enrichmentStatus =
    typeof res.enrichment_status === "string"
      ? res.enrichment_status
      : typeof rawEnrichmentObj?.enrichment_status === "string"
        ? rawEnrichmentObj.enrichment_status
        : typeof rawEnrichmentObj?.status === "string"
          ? rawEnrichmentObj.status
          : null;

  return {
    event_id: res.event_id ?? null,
    ingestion_id: res.ingestion_id,
    raw_envelope_id: res.raw_envelope_id,
    timestamp: res.timestamp ?? null,
    source: res.source_type,
    sensor_id: res.sensor_id ?? null,
    event_category: res.event_category ?? null,
    event_type: res.event_type ?? null,
    host: res.host ?? null,
    user: res.user ?? null,
    source_ip: res.source_ip ?? null,
    destination_ip: res.destination_ip ?? null,
    source_port: res.source_port ?? null,
    destination_port: res.destination_port ?? null,
    protocol: res.protocol ?? null,
    process: res.process ?? null,
    file_hash: res.file_hash ?? null,
    domain: res.domain ?? null,
    command_line: res.command_line ?? null,
    severity: res.severity ?? null,
    metadata: safeMetadata,
    normalization_status: res.normalization_status,
    warnings: Array.isArray(res.normalization_warnings) ? res.normalization_warnings : [],
    errors: Array.isArray(res.normalization_errors) ? res.normalization_errors : [],
    enrichment_status: enrichmentStatus,
    enrichment: normalizeEnrichmentContext(rawEnrichment, enrichmentStatus),
    created_at: res.created_at,
  };
}

/**
 * Builds a URL query string for GET /api/v1/events/normalized from non-empty params.
 */
export function buildNormalizedEventsQueryString(
  params: NormalizedEventsQueryParams = {}
): string {
  const searchParams = new URLSearchParams();
  const safeLimit = Math.max(1, Math.min(params.limit ?? DEFAULT_RECENT_EVENTS_LIMIT, MAX_QUERY_LIMIT));
  searchParams.set("limit", String(safeLimit));

  if (typeof params.offset === "number" && !Number.isNaN(params.offset)) {
    const safeOffset = Math.max(0, Math.min(Math.floor(params.offset), MAX_QUERY_OFFSET));
    if (safeOffset > 0) {
      searchParams.set("offset", String(safeOffset));
    }
  }

  const trimmedSearch = params.search?.trim();
  if (trimmedSearch) {
    searchParams.set("search", trimmedSearch.slice(0, MAX_SEARCH_LENGTH));
  }

  if (params.source_type) {
    searchParams.set("source_type", params.source_type);
  }

  if (params.normalization_status) {
    searchParams.set("normalization_status", params.normalization_status);
  }

  if (params.event_category) {
    searchParams.set("event_category", params.event_category);
  }

  const cleanedEventType = params.event_type?.trim().toLowerCase();
  if (cleanedEventType) {
    searchParams.set("event_type", cleanedEventType.slice(0, MAX_EVENT_TYPE_LENGTH));
  }

  if (typeof params.severity === "number" && params.severity >= 1 && params.severity <= 5) {
    searchParams.set("severity", String(params.severity));
  }

  const trimmedStart = params.start_time?.trim();
  if (trimmedStart) {
    searchParams.set("start_time", trimmedStart);
  }

  const trimmedEnd = params.end_time?.trim();
  if (trimmedEnd) {
    searchParams.set("end_time", trimmedEnd);
  }

  if (params.sort_by) {
    searchParams.set("sort_by", params.sort_by);
  }

  if (params.sort_order) {
    searchParams.set("sort_order", params.sort_order);
  }

  return searchParams.toString();
}

/**
 * Queries normalized security events from GET /api/v1/events/normalized with
 * backend filter, sort, and pagination parameters.
 */
export const queryNormalizedEvents = async (
  params: NormalizedEventsQueryParams = {}
): Promise<NormalizedEventListResult> => {
  const safeLimit = Math.max(1, Math.min(params.limit ?? DEFAULT_RECENT_EVENTS_LIMIT, MAX_QUERY_LIMIT));
  const safeOffset =
    typeof params.offset === "number" && !Number.isNaN(params.offset)
      ? Math.max(0, Math.min(Math.floor(params.offset), MAX_QUERY_OFFSET))
      : 0;
  const queryString = buildNormalizedEventsQueryString({
    ...params,
    limit: safeLimit,
    offset: safeOffset,
  });

  const res = await ApiClient.get<NormalizedEventResponse[] | NormalizedEventsEnvelope>(
    `${EVENTS_NORMALIZED_ENDPOINT}?${queryString}`,
    { cache: "no-store" }
  );

  if (Array.isArray(res)) {
    const items = res
      .filter((item): item is NormalizedEventResponse => Boolean(item && typeof item === "object"))
      .slice(0, safeLimit)
      .map(mapNormalizedEventResponse);
    return {
      items,
      count: items.length,
      limit: safeLimit,
      offset: safeOffset,
      has_more: false,
    };
  }

  if (res && typeof res === "object" && Array.isArray(res.items)) {
    const items = res.items
      .filter((item): item is NormalizedEventResponse => Boolean(item && typeof item === "object"))
      .slice(0, safeLimit)
      .map(mapNormalizedEventResponse);
    const resolvedTotal = typeof res.total === "number" ? res.total : undefined;
    const resolvedOffset = typeof res.offset === "number" ? res.offset : safeOffset;
    const resolvedHasMore =
      typeof res.has_more === "boolean"
        ? res.has_more
        : typeof resolvedTotal === "number"
          ? resolvedOffset + items.length < resolvedTotal
          : false;
    return {
      items,
      count: typeof res.count === "number" ? res.count : items.length,
      limit: typeof res.limit === "number" ? res.limit : safeLimit,
      total: resolvedTotal,
      offset: resolvedOffset,
      has_more: resolvedHasMore,
    };
  }

  return {
    items: [],
    count: 0,
    limit: safeLimit,
    offset: safeOffset,
    has_more: false,
  };
};

/**
 * Retrieves recent normalized security events from GET /api/v1/events/normalized.
 */
export const fetchNormalizedEvents = async (
  limit = DEFAULT_RECENT_EVENTS_LIMIT
): Promise<NormalizedSecurityEvent[]> => {
  const result = await queryNormalizedEvents({ limit });
  return result.items;
};

/**
 * Retrieves a single normalized security event by event_id from
 * GET /api/v1/events/normalized/{event_id}.
 */
export const fetchNormalizedEventById = async (
  eventId: string
): Promise<NormalizedSecurityEvent> => {
  const res = await ApiClient.get<NormalizedEventResponse>(
    `${EVENTS_NORMALIZED_ENDPOINT}/${encodeURIComponent(eventId)}`,
    { cache: "no-store" }
  );
  if (!res || typeof res !== "object" || typeof res.ingestion_id !== "string") {
    throw new Error("Malformed response from normalized event endpoint");
  }
  return mapNormalizedEventResponse(res);
};

/**
 * Retrieves enrichment context for a normalized event from
 * GET /api/v1/events/normalized/{event_id}/enrichment.
 */
export const fetchNormalizedEventEnrichment = async (
  eventId: string
): Promise<EventEnrichmentContext> => {
  const res = await ApiClient.get<Record<string, unknown>>(
    `${EVENTS_NORMALIZED_ENDPOINT}/${encodeURIComponent(eventId)}/enrichment`,
    { cache: "no-store" }
  );
  const mapped = normalizeEnrichmentContext(res);
  if (!mapped) {
    throw new Error("Malformed response from normalized event enrichment endpoint");
  }
  return mapped;
};

/**
 * Triggers or retries deterministic enrichment for a normalized event via
 * POST /api/v1/events/normalized/{event_id}/enrich.
 */
export const retryNormalizedEventEnrichment = async (
  eventId: string,
  forceRetry = false
): Promise<EventEnrichmentContext> => {
  const suffix = forceRetry ? "?force_retry=true" : "";
  const res = await ApiClient.post<Record<string, unknown>>(
    `${EVENTS_NORMALIZED_ENDPOINT}/${encodeURIComponent(eventId)}/enrich${suffix}`
  );
  const mapped = normalizeEnrichmentContext(res);
  if (!mapped) {
    throw new Error("Malformed response from event enrich endpoint");
  }
  return mapped;
};
