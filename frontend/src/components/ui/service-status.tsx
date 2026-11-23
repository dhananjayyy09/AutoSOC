import * as React from "react"
import { StatusIndicator } from "@/components/ui/status-indicator"
import { Button } from "@/components/ui/button"
import { ShieldCheck, ShieldAlert, RefreshCw } from "lucide-react"

export interface ServiceStatusProps {
  status: "loading" | "online" | "warning" | "offline"
  serviceName: string
  description?: string
  onRetry?: () => void
  isRetrying?: boolean
}

export function ServiceStatus({ status, serviceName, description, onRetry, isRetrying }: ServiceStatusProps) {
  const getIconWrapperClass = () => {
    switch (status) {
      case "online":
        return "bg-green-500/10"
      case "warning":
        return "bg-yellow-500/10"
      case "loading":
        return "bg-muted"
      case "offline":
      default:
        return "bg-red-500/10"
    }
  }

  const getStatusText = () => {
    if (description) return description
    switch (status) {
      case "online":
        return "Available"
      case "warning":
        return "Degraded"
      case "loading":
        return "Checking..."
      case "offline":
      default:
        return "Unavailable"
    }
  }

  return (
    <div className="flex items-center justify-between rounded-lg border bg-card p-4">
      <div className="flex items-center space-x-4">
        <div className={`rounded-full p-2 ${getIconWrapperClass()}`}>
          {status === "online" ? (
            <ShieldCheck className="h-4 w-4 text-green-500" />
          ) : status === "warning" ? (
            <ShieldAlert className="h-4 w-4 text-yellow-500" />
          ) : status === "loading" ? (
            <ShieldAlert className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ShieldAlert className="h-4 w-4 text-red-500" />
          )}
        </div>
        <div className="space-y-1">
          <p className="text-sm font-medium leading-none">{serviceName}</p>
          <p className="text-xs text-muted-foreground">{getStatusText()}</p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <StatusIndicator status={status} />
        {(status === "offline" || status === "warning") && onRetry && (
          <Button 
            variant="ghost" 
            size="icon" 
            onClick={onRetry} 
            disabled={isRetrying}
            className="h-8 w-8"
          >
            <RefreshCw className={`h-4 w-4 ${isRetrying ? "animate-spin" : ""}`} />
          </Button>
        )}
      </div>
    </div>
  )
}
