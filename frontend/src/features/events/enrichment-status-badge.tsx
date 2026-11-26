import * as React from "react"
import { AlertTriangle, CheckCircle2, HelpCircle, MinusCircle, XCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

interface EnrichmentPresentation {
  label: string
  className: string
  Icon: React.ComponentType<{ className?: string }>
}

export function getEnrichmentStatusPresentation(
  status: string | null | undefined
): EnrichmentPresentation {
  const normalized = typeof status === "string" ? status.trim().toLowerCase() : ""

  switch (normalized) {
    case "enriched":
      return {
        label: "Enriched",
        className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
        Icon: CheckCircle2,
      }
    case "partial":
    case "partially_enriched":
    case "enriched_with_warnings":
      return {
        label: "Partial Enrichment",
        className: "border-amber-500/40 bg-amber-500/10 text-amber-300",
        Icon: AlertTriangle,
      }
    case "failed":
      return {
        label: "Enrichment Failed",
        className: "border-red-500/40 bg-red-500/10 text-red-300",
        Icon: XCircle,
      }
    case "skipped":
      return {
        label: "Skipped",
        className: "border-slate-500/40 bg-slate-500/10 text-slate-300",
        Icon: MinusCircle,
      }
    case "not_enriched":
    case "none":
      return {
        label: "Not Enriched",
        className: "border-muted-foreground/40 bg-muted/40 text-muted-foreground",
        Icon: MinusCircle,
      }
    case "":
      return {
        label: "Not Available",
        className: "border-muted-foreground/40 bg-muted/40 text-muted-foreground",
        Icon: MinusCircle,
      }
    default:
      return {
        label: `Unknown (${status})`,
        className: "border-muted-foreground/40 bg-muted/40 text-muted-foreground",
        Icon: HelpCircle,
      }
  }
}

export interface EnrichmentStatusBadgeProps {
  status: string | null | undefined
  className?: string
}

export function EnrichmentStatusBadge({ status, className }: EnrichmentStatusBadgeProps) {
  const { label, className: toneClass, Icon } = getEnrichmentStatusPresentation(status)

  return (
    <Badge
      variant="outline"
      className={cn("inline-flex items-center gap-1.5 font-medium", toneClass, className)}
      aria-label={`Enrichment status: ${label}`}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span>{label}</span>
    </Badge>
  )
}
