/**
 * System Feature Module — Day 5
 * Exports all system health / readiness integration primitives.
 * UI components, hooks, API functions, and types are consolidated here
 * so that feature pages and tests import from a single, stable surface.
 */
export { HealthCheck } from "@/components/health-check";
export { useHealthCheck } from "@/hooks/use-health-check";
export { useReadiness } from "@/hooks/use-readiness";
export { useApiRequest } from "@/hooks/use-api-request";
export {
  checkHealth,
  checkReadiness,
  checkSystemInfo,
  ApiClient,
  ApiError,
  isAbortError,
  isNetworkError,
} from "@/lib/api";
export type {
  HealthStatus,
  ReadinessState,
  ReadinessResponse,
  ReadinessResult,
  InfrastructureReadiness,
  HealthCheckResponse,
  SystemInfoResponse,
  AsyncState,
  RequestStatus,
} from "@/types";
