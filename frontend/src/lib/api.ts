import type {
  BackendValidationErrorItem,
  EventIngestionRequest,
  EventIngestionResponse,
  HealthCheckResponse,
  IngestedEventRecord,
  ReadinessResponse,
  ReadinessResult,
  RecentEventsEnvelope,
  SystemInfoResponse,
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
export const DEFAULT_RECENT_EVENTS_LIMIT = 20;

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
