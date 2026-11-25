import * as React from "react"
import { AlertTriangle, CheckCircle2, Clock, HelpCircle, XCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"
import type { NormalizationStatus } from "@/types"

interface StatusPresentation {
  label: string
  className: string
  Icon: React.ComponentType<{ className?: string }>
}

function getStatusPresentation(status: NormalizationStatus | null | undefined): StatusPresentation {
  const normalized = typeof status === "string" ? status.trim().toLowerCase() : ""

  switch (normalized) {
    case "normalized":
      return {
        label: "Normalized",
        className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
        Icon: CheckCircle2,
      }
    case "normalized_with_warnings":
      return {
        label: "Normalized with Warnings",
        className: "border-amber-500/40 bg-amber-500/10 text-amber-300",
        Icon: AlertTriangle,
      }
    case "accepted":
      return {
        label: "Accepted (Raw)",
        className: "border-blue-500/40 bg-blue-500/10 text-blue-300",
        Icon: Clock,
      }
    case "accepted_with_warnings":
      return {
        label: "Accepted with Warnings",
        className: "border-amber-500/40 bg-amber-500/10 text-amber-300",
        Icon: AlertTriangle,
      }
    case "pending":
      return {
        label: "Pending Normalization",
        className: "border-slate-500/40 bg-slate-500/10 text-slate-300",
        Icon: Clock,
      }
    case "unsupported":
      return {
        label: "Unsupported Source",
        className: "border-orange-500/40 bg-orange-500/10 text-orange-300",
        Icon: AlertTriangle,
      }
    case "rejected":
      return {
        label: "Rejected",
        className: "border-red-500/40 bg-red-500/10 text-red-300",
        Icon: XCircle,
      }
    case "failed":
      return {
        label: "Normalization Failed",
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

export interface NormalizationStatusBadgeProps {
  status: NormalizationStatus | null | undefined
  warnings?: string[]
  errors?: string[]
  className?: string
}

export function NormalizationStatusBadge({
  status,
  warnings,
  errors,
  className,
}: NormalizationStatusBadgeProps) {
  const { label, className: toneClass, Icon } = getStatusPresentation(status)
  const hasWarnings = Boolean(warnings && warnings.length > 0)
  const hasErrors = Boolean(errors && errors.length > 0)

  return (
    <div className={cn("space-y-2", className)}>
      <Badge
        variant="outline"
        className={cn("inline-flex items-center gap-1.5 font-medium", toneClass)}
        aria-label={`Normalization status: ${label}`}
      >
        <Icon className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span>{label}</span>
      </Badge>

      {hasWarnings && (
        <ul
          aria-label="Normalization warnings"
          className="ml-4 list-disc space-y-0.5 text-xs text-amber-300"
        >
          {warnings!.map((warning, idx) => (
            <li key={`warn-${idx}`}>{warning}</li>
          ))}
        </ul>
      )}

      {hasErrors && (
        <ul
          role="alert"
          aria-label="Normalization errors"
          className="ml-4 list-disc space-y-0.5 text-xs text-destructive"
        >
          {errors!.map((errorMsg, idx) => (
            <li key={`err-${idx}`}>{errorMsg}</li>
          ))}
        </ul>
      )}
    </div>
  )
}
