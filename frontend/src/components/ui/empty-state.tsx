import * as React from "react"
import { cn } from "@/lib/utils"
import { LucideIcon, Database } from "lucide-react"
import { Button } from "@/components/ui/button"

interface EmptyStateProps {
  /** Primary heading. Keep honest — no fake counts. */
  title?: string
  /** Supporting message. Can describe what this area will show when data arrives. */
  description?: string
  /** Optional icon override. Defaults to Database. */
  icon?: LucideIcon
  /** Optional action label (e.g. "Refresh"). No action is shown when omitted. */
  actionLabel?: string
  /** Handler for the optional action button. */
  onAction?: () => void
  /** Disables the action button (e.g. while refreshing). */
  isActionLoading?: boolean
  /** Additional className for the container. */
  className?: string
}

export function EmptyState({
  title = "No data available",
  description = "There is currently no data to display in this view.",
  icon: Icon = Database,
  actionLabel,
  onAction,
  isActionLoading = false,
  className,
}: EmptyStateProps) {
  return (
    <div
      role="status"
      aria-label={title}
      className={cn(
        "flex h-[400px] w-full flex-col items-center justify-center space-y-4 rounded-lg border border-dashed p-8 text-center animate-in fade-in-50",
        className
      )}
    >
      <div className="rounded-full bg-muted p-4" aria-hidden="true">
        <Icon className="h-8 w-8 text-muted-foreground" />
      </div>
      <div className="space-y-1">
        <h3 className="font-medium tracking-tight">{title}</h3>
        <p className="text-sm text-muted-foreground max-w-sm">{description}</p>
      </div>
      {actionLabel && onAction && (
        <Button
          variant="outline"
          size="sm"
          onClick={onAction}
          disabled={isActionLoading}
          aria-label={isActionLoading ? "Loading…" : actionLabel}
        >
          {isActionLoading ? "Loading…" : actionLabel}
        </Button>
      )}
    </div>
  )
}
