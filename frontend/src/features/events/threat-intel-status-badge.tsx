import * as React from "react"
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileWarning,
  Gauge,
  HelpCircle,
  MinusCircle,
  RotateCcw,
  ServerOff,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import type { ThreatIntelLookupStatus } from "@/types"

interface BadgePresentation {
  label: string
  className: string
  Icon: React.ComponentType<{ className?: string }>
}

export function getLookupStatusPresentation(
  status: ThreatIntelLookupStatus | null | undefined
): BadgePresentation {
  const normalized = typeof status === "string" ? status.trim().toLowerCase() : ""

  switch (normalized) {
    case "not_queried":
      return {
        label: "Not Queried",
        className: "border-muted-foreground/40 bg-muted/40 text-muted-foreground",
        Icon: MinusCircle,
      }
    case "offline_only":
      return {
        label: "Offline Only",
        className: "border-muted-foreground/40 bg-muted/40 text-muted-foreground",
        Icon: MinusCircle,
      }
    case "pending":
    case "lookup_pending":
      return {
        label: "Lookup Pending",
        className: "border-blue-500/40 bg-blue-500/10 text-blue-300",
        Icon: Clock,
      }
    case "completed":
    case "lookup_completed":
    case "ok":
    case "success":
    case "found":
      return {
        label: "Lookup Completed",
        className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
        Icon: CheckCircle2,
      }
    case "cache_hit":
      return {
        label: "Cached Hit",
        className: "border-blue-500/40 bg-blue-500/10 text-blue-300",
        Icon: CheckCircle2,
      }
    case "no_result":
    case "not_found":
    case "no_data":
      return {
        label: "No Result",
        className: "border-slate-500/40 bg-slate-500/10 text-slate-300",
        Icon: MinusCircle,
      }
    case "timeout":
      return {
        label: "Timed Out",
        className: "border-amber-500/40 bg-amber-500/10 text-amber-300",
        Icon: Clock,
      }
    case "provider_unavailable":
    case "unavailable":
      return {
        label: "Provider Unavailable",
        className: "border-amber-500/40 bg-amber-500/10 text-amber-300",
        Icon: ServerOff,
      }
    case "rate_limited":
    case "rate_limit":
      return {
        label: "Rate Limited",
        className: "border-amber-500/40 bg-amber-500/10 text-amber-300",
        Icon: Gauge,
      }
    case "circuit_open":
    case "circuit_breaker_open":
      return {
        label: "Circuit Breaker Open",
        className: "border-red-500/40 bg-red-500/10 text-red-300",
        Icon: AlertOctagon,
      }
    case "retry_exhausted":
      return {
        label: "Retry Exhausted",
        className: "border-red-500/40 bg-red-500/10 text-red-300",
        Icon: RotateCcw,
      }
    case "skipped":
      return {
        label: "Skipped",
        className: "border-slate-500/40 bg-slate-500/10 text-slate-300",
        Icon: MinusCircle,
      }
    case "skipped_limit":
      return {
        label: "Skipped (Limit)",
        className: "border-slate-500/40 bg-slate-500/10 text-slate-300",
        Icon: MinusCircle,
      }
    case "unsupported":
    case "unsupported_observable":
      return {
        label: "Unsupported",
        className: "border-slate-500/40 bg-slate-500/10 text-slate-300",
        Icon: MinusCircle,
      }
    case "invalid_response":
    case "malformed_response":
      return {
        label: "Malformed Response",
        className: "border-red-500/40 bg-red-500/10 text-red-300",
        Icon: FileWarning,
      }
    case "failed":
    case "lookup_failed":
    case "error":
      return {
        label: "Lookup Failed",
        className: "border-red-500/40 bg-red-500/10 text-red-300",
        Icon: XCircle,
      }
    default:
      return {
        label: normalized ? `Unknown (${status})` : "Unknown",
        className: "border-muted-foreground/40 bg-muted/40 text-muted-foreground",
        Icon: HelpCircle,
      }
  }
}

export function ThreatLookupStatusBadge({
  status,
  className,
}: {
  status: ThreatIntelLookupStatus
  className?: string
}) {
  const { label, className: toneClass, Icon } = getLookupStatusPresentation(status)
  return (
    <Badge
      variant="outline"
      className={cn("inline-flex items-center gap-1 font-medium text-[11px]", toneClass, className)}
      aria-label={`Lookup status: ${label}`}
    >
      <Icon className="h-3 w-3 shrink-0" aria-hidden="true" />
      <span>{label}</span>
    </Badge>
  )
}

export function getVerdictPresentation(verdict: string): BadgePresentation {
  const normalized = verdict.trim().toLowerCase()

  switch (normalized) {
    case "malicious":
      return {
        label: `verdict: ${verdict}`,
        className: "border-red-500/40 bg-red-500/10 text-red-300",
        Icon: ShieldAlert,
      }
    case "suspicious":
      return {
        label: `verdict: ${verdict}`,
        className: "border-amber-500/40 bg-amber-500/10 text-amber-300",
        Icon: AlertTriangle,
      }
    case "clean":
    case "benign":
    case "harmless":
      return {
        label: `verdict: ${verdict}`,
        className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
        Icon: ShieldCheck,
      }
    case "unknown":
    default:
      return {
        label: `verdict: ${verdict}`,
        className: "border-slate-500/40 bg-slate-500/10 text-slate-300",
        Icon: HelpCircle,
      }
  }
}

export function ThreatVerdictBadge({
  verdict,
  className,
}: {
  verdict: string
  className?: string
}) {
  const { label, className: toneClass, Icon } = getVerdictPresentation(verdict)
  return (
    <Badge
      variant="outline"
      className={cn("inline-flex items-center gap-1 font-mono text-[11px]", toneClass, className)}
      aria-label={`Reputation verdict: ${verdict}`}
    >
      <Icon className="h-3 w-3 shrink-0" aria-hidden="true" />
      <span>{label}</span>
    </Badge>
  )
}
