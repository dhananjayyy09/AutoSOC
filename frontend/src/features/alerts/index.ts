/**
 * Alerts Feature Module Foundation
 * AutoSOC Phase 1 – Architecture and Infrastructure
 */
import type { Alert, AlertStatus, SeverityLevel } from "@/types";

export type { Alert, AlertStatus, SeverityLevel };

export const ALERTS_CONFIG = {
  title: "Alerts",
  description: "Real-time security alerts requiring triage and initial analysis.",
  emptyMessage: "No alerts have been triggered.",
} as const;
