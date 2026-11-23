/**
 * Incidents Feature Module Foundation
 * AutoSOC Phase 1 – Architecture and Infrastructure
 */
import type { Incident, IncidentStatus, SeverityLevel } from "@/types";

export type { Incident, IncidentStatus, SeverityLevel };

export const INCIDENTS_CONFIG = {
  title: "Incidents",
  description: "Confirmed security incidents escalated from alerts or manual creation.",
  emptyMessage: "No active incidents.",
} as const;
