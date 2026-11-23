// ---------------------------------------------------------------------------
// AutoSOC – shared frontend types
// Authoritative definitions for security severity, system health, and
// foundation domain contracts for Phase 1 & 2 security workflows.
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

/** Generic API response wrapper. */
export interface ApiResponse<T = unknown> {
  data: T;
  message?: string;
}

/** Health endpoint response shape (GET /health). */
export interface HealthCheckResponse {
  status: string;
  service: string;
}

// ---------------------------------------------------------------------------
// Security Domain Contracts (Phase 1 Foundation for Future Workflows)
// ---------------------------------------------------------------------------

/** Alert lifecycle status. */
export type AlertStatus = "open" | "investigating" | "resolved" | "false_positive";

/** Alert domain model contract. */
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

/** Incident lifecycle status. */
export type IncidentStatus = "open" | "triaged" | "contained" | "resolved" | "closed";

/** Incident domain model contract. */
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

/** Investigation lifecycle status. */
export type InvestigationStatus = "active" | "completed" | "archived";

/** Investigation domain model contract. */
export interface Investigation {
  id: string;
  title: string;
  incidentId?: string;
  status: InvestigationStatus;
  findingsCount: number;
  leadAnalyst?: string;
  createdAt: string;
}

/** Threat intelligence indicator type. */
export type ThreatIndicatorType = "ip" | "domain" | "hash" | "url";

/** Threat intelligence indicator domain model contract. */
export interface ThreatIntelIndicator {
  id: string;
  type: ThreatIndicatorType;
  value: string;
  confidence: number;
  severity: SeverityLevel;
  source: string;
  tags: string[];
}

/** Threat hunting campaign status. */
export type HuntingCampaignStatus = "draft" | "running" | "completed";

/** Threat hunting campaign domain model contract. */
export interface HuntingCampaign {
  id: string;
  name: string;
  query: string;
  status: HuntingCampaignStatus;
  findingsCount: number;
  createdAt: string;
}
