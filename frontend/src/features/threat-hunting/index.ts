/**
 * Threat Hunting Feature Module Foundation
 * AutoSOC Phase 1 – Architecture and Infrastructure
 */
import type { HuntingCampaign, HuntingCampaignStatus } from "@/types";

export type { HuntingCampaign, HuntingCampaignStatus };

export const THREAT_HUNTING_CONFIG = {
  title: "Threat Hunting",
  description: "Proactive searching for hidden threats within the network.",
  emptyMessage: "No active hunting campaigns.",
} as const;
