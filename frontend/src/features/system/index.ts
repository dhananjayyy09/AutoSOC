/**
 * System Health & Readiness Feature Module Foundation
 * AutoSOC Phase 1 – Architecture and Infrastructure
 */
export { HealthCheck } from "@/components/health-check";
export { useHealthCheck } from "@/hooks/use-health-check";
export { useReadiness } from "@/hooks/use-readiness";
export { checkHealth, checkReadiness, ApiClient, ApiError } from "@/lib/api";
export type {
  HealthStatus,
  ReadinessState,
  ReadinessResponse,
  ReadinessResult,
  InfrastructureReadiness,
  HealthCheckResponse,
} from "@/types";
