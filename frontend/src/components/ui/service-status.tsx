import * as React from "react"
import { StatusIndicator } from "@/components/ui/status-indicator"
import { Button } from "@/components/ui/button"
import { ShieldCheck, ShieldAlert, RefreshCw } from "lucide-react"

export interface ServiceStatusProps {
  status: "loading" | "online" | "offline"
  serviceName: string
  onRetry?: () => void
  isRetrying?: boolean
}

export function ServiceStatus({ status, serviceName, onRetry, isRetrying }: ServiceStatusProps) {
  return (
    <div className="flex items-center justify-between rounded-lg border bg-card p-4">
      <div className="flex items-center space-x-4">
        <div className={`rounded-full p-2 ${status === "online" ? "bg-green-500/10" : status === "loading" ? "bg-muted" : "bg-red-500/10"}`}>
          {status === "online" ? (
            <ShieldCheck className="h-4 w-4 text-green-500" />
          ) : status === "loading" ? (
            <ShieldAlert className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ShieldAlert className="h-4 w-4 text-red-500" />
          )}
        </div>
        <div className="space-y-1">
          <p className="text-sm font-medium leading-none">{serviceName}</p>
          <p className="text-xs text-muted-foreground">
            {status === "online" ? "Available" : status === "loading" ? "Checking..." : "Unavailable"}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <StatusIndicator status={status === "loading" ? "loading" : status === "online" ? "online" : "offline"} />
        {status === "offline" && onRetry && (
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
