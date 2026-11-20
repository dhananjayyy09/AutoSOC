// ---------------------------------------------------------------------------
// AutoSOC – shared frontend types
// Only types that are justified by existing UI components are defined here.
// Do NOT invent the full future API schema on Day 1 or Day 2.
// ---------------------------------------------------------------------------

/** Security severity levels used across the platform. */
export type SeverityLevel = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Status of a backend health/liveness check. */
export type HealthStatus = "connected" | "unavailable";

/** Infrastructure readiness statuses. */
export interface InfrastructureReadiness {
  postgres: boolean;
  redis: boolean;
  qdrant: boolean;
  kafka: boolean;
}

/** Conceptual readiness state: ready, degraded, or unavailable. */
export type ReadinessState = "ready" | "degraded" | "unavailable";

/** Raw readiness response from GET /ready (matching backend contract). */
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

/** Generic API response wrapper (can be extended later). */
export interface ApiResponse<T = unknown> {
  data: T;
  message?: string;
}

/** Health endpoint response shape (GET /health). */
export interface HealthCheckResponse {
  status: string;
  service: string;
}
