import * as React from "react"
import { AlertCircle } from "lucide-react"
import { Button } from "@/components/ui/button"

export function ErrorState({ 
  title = "An error occurred", 
  description = "We couldn't load the requested data. Please try again later.",
  onRetry
}: { 
  title?: string
  description?: string 
  onRetry?: () => void
}) {
  return (
    <div className="flex h-[400px] w-full flex-col items-center justify-center space-y-4 rounded-lg border border-destructive/20 bg-destructive/5 p-8 text-center animate-in fade-in-50">
      <div className="rounded-full bg-destructive/10 p-4">
        <AlertCircle className="h-8 w-8 text-destructive" />
      </div>
      <div className="space-y-1">
        <h3 className="font-medium text-destructive tracking-tight">{title}</h3>
        <p className="text-sm text-destructive/80 max-w-sm">{description}</p>
      </div>
      {onRetry && (
        <Button variant="outline" onClick={onRetry} className="mt-4 border-destructive/20 hover:bg-destructive/10 text-destructive">
          Try Again
        </Button>
      )}
    </div>
  )
}
