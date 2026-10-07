// ---------------------------------------------------------------------------
// AutoSOC – shared frontend types
// Only types that are justified by existing UI components are defined here.
// Do NOT invent the full future API schema on Day 1.
// ---------------------------------------------------------------------------

/** Security severity levels used across the platform. */
export type SeverityLevel = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Status of a backend health check. */
export type HealthStatus = "connected" | "unavailable";

/** Generic API response wrapper (can be extended later). */
export interface ApiResponse<T = unknown> {
  data: T;
  message?: string;
}

/** Health endpoint response shape. */
export interface HealthCheckResponse {
  status: string;
  version?: string;
  uptime?: number;
}
