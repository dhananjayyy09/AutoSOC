import type { HealthCheckResponse, ReadinessResponse, ReadinessResult } from "@/types";

const getBaseUrl = (): string => {
  const envUrl = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
  return envUrl.replace(/\/+$/, "");
};

export const API_BASE_URL = getBaseUrl();
const DEFAULT_TIMEOUT = 10000; // 10 seconds

export class ApiError extends Error {
  status: number;
  statusText: string;
  data?: unknown;

  constructor(status: number, statusText: string, data?: unknown) {
    super(`API Error: ${status} ${statusText}`);
    this.name = "ApiError";
    this.status = status;
    this.statusText = statusText;
    this.data = data;
  }
}

export class ApiClient {
  /**
   * Centralized HTTP request dispatcher for all API communications.
   */
  static async request<T = unknown>(
    endpoint: string,
    options: RequestInit = {},
    timeout = DEFAULT_TIMEOUT
  ): Promise<T> {
    const baseUrl = getBaseUrl();
    const normalizedEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
    const url = `${baseUrl}${normalizedEndpoint}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

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
          // ignore parsing error if response body is empty or not JSON
        }
        throw new ApiError(response.status, response.statusText, errorData);
      }

      return (await response.json()) as T;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  static async get<T = unknown>(endpoint: string, options: RequestInit = {}, timeout = DEFAULT_TIMEOUT): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: "GET" }, timeout);
  }

  static async post<T = unknown>(endpoint: string, body?: unknown, options: RequestInit = {}, timeout = DEFAULT_TIMEOUT): Promise<T> {
    return this.request<T>(
      endpoint,
      {
        ...options,
        method: "POST",
        body: body !== undefined ? JSON.stringify(body) : undefined,
      },
      timeout
    );
  }

  static async put<T = unknown>(endpoint: string, body?: unknown, options: RequestInit = {}, timeout = DEFAULT_TIMEOUT): Promise<T> {
    return this.request<T>(
      endpoint,
      {
        ...options,
        method: "PUT",
        body: body !== undefined ? JSON.stringify(body) : undefined,
      },
      timeout
    );
  }

  static async delete<T = unknown>(endpoint: string, options: RequestInit = {}, timeout = DEFAULT_TIMEOUT): Promise<T> {
    return this.request<T>(endpoint, { ...options, method: "DELETE" }, timeout);
  }
}

/**
 * Checks application liveness by calling GET /health.
 * Returns 'connected' if process is alive, 'unavailable' otherwise.
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
 * Checks infrastructure readiness by calling GET /ready.
 * Returns:
 * - 'ready': HTTP 200 and all infrastructure components connected
 * - 'degraded': HTTP 503 or any dependency unavailable
 * - 'unavailable': Network error or backend unreachable
 */
export const checkReadiness = async (): Promise<ReadinessResult> => {
  try {
    const res = await ApiClient.get<ReadinessResponse>("/ready", { cache: "no-store" });
    const isReady =
      res &&
      res.status === "ok" &&
      res.postgres === true &&
      res.redis === true &&
      res.qdrant === true &&
      res.kafka === true;

    return {
      state: isReady ? "ready" : "degraded",
      data: {
        status: res?.status || "ok",
        postgres: Boolean(res?.postgres),
        redis: Boolean(res?.redis),
        qdrant: Boolean(res?.qdrant),
        kafka: Boolean(res?.kafka),
      },
    };
  } catch (error) {
    // If backend returned HTTP 503 (FastAPI raises HTTPException with detail dict)
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
