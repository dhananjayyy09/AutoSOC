/**
 * Threat Intelligence Feature Module Foundation
 * AutoSOC Phase 1 – Architecture and Infrastructure
 */
import type { ThreatIntelIndicator, ThreatIndicatorType, SeverityLevel } from "@/types";

export type { ThreatIntelIndicator, ThreatIndicatorType, SeverityLevel };

export const THREAT_INTEL_CONFIG = {
  title: "Threat Intelligence",
  description: "Indicators of Compromise (IoCs), actor profiles, and global threat data.",
  emptyMessage: "No intelligence feeds configured.",
} as const;
