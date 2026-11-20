import type { HealthCheckResponse, ReadinessResponse, ReadinessResult } from "@/types";

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";
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
  static async get(endpoint: string, options: RequestInit = {}, timeout = DEFAULT_TIMEOUT) {
    const url = `${API_BASE_URL}${endpoint}`;
    
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
      
      return response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
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
    const res = await ApiClient.get("/health", { cache: "no-store" });
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
    const res: ReadinessResponse = await ApiClient.get("/ready", { cache: "no-store" });
    const isReady =
      res.status === "ok" &&
      res.postgres === true &&
      res.redis === true &&
      res.qdrant === true &&
      res.kafka === true;

    return {
      state: isReady ? "ready" : "degraded",
      data: {
        status: res.status || "ok",
        postgres: Boolean(res.postgres),
        redis: Boolean(res.redis),
        qdrant: Boolean(res.qdrant),
        kafka: Boolean(res.kafka),
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
