import * as React from "react"
import { AlertCircle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

interface ErrorStateProps {
  title?: string
  description?: string
  onRetry?: () => void
  isRetrying?: boolean
  className?: string
}

export function ErrorState({
  title = "An error occurred",
  description = "We couldn't load the requested data. Please try again.",
  onRetry,
  isRetrying = false,
  className,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      aria-live="assertive"
      className={cn(
        "flex h-[400px] w-full flex-col items-center justify-center space-y-4 rounded-lg border border-destructive/20 bg-destructive/5 p-8 text-center animate-in fade-in-50",
        className
      )}
    >
      <div className="rounded-full bg-destructive/10 p-4" aria-hidden="true">
        <AlertCircle className="h-8 w-8 text-destructive" />
      </div>
      <div className="space-y-1">
        <h3 className="font-medium text-destructive tracking-tight">{title}</h3>
        <p className="text-sm text-destructive/80 max-w-sm">{description}</p>
      </div>
      {onRetry && (
        <Button
          variant="outline"
          onClick={onRetry}
          disabled={isRetrying}
          aria-label={isRetrying ? "Retrying…" : "Try again"}
          className="mt-4 border-destructive/20 hover:bg-destructive/10 text-destructive"
        >
          {isRetrying ? "Retrying…" : "Try Again"}
        </Button>
      )}
    </div>
  )
}
