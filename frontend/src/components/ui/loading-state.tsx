import * as React from "react"
import { Loader2 } from "lucide-react"
import { cn } from "@/lib/utils"

interface LoadingStateProps {
  text?: string
  className?: string
}

export function LoadingState({ text = "Loading…", className }: LoadingStateProps) {
  return (
    <div
      role="status"
      aria-label={text}
      aria-live="polite"
      className={cn(
        "flex h-[400px] w-full flex-col items-center justify-center space-y-4 rounded-lg border border-dashed p-8 text-center animate-in fade-in-50",
        className
      )}
    >
      <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" aria-hidden="true" />
      <h3 className="text-sm font-medium text-muted-foreground">{text}</h3>
    </div>
  )
}
