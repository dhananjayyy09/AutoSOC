/**
 * Investigations Feature Module Foundation
 * AutoSOC Phase 1 – Architecture and Infrastructure
 */
import type { Investigation, InvestigationStatus } from "@/types";

export type { Investigation, InvestigationStatus };

export const INVESTIGATIONS_CONFIG = {
  title: "Investigations",
  description: "Deep-dive analysis of security events, evidence collection, and multi-agent correlation.",
  emptyMessage: "No active investigations.",
} as const;
