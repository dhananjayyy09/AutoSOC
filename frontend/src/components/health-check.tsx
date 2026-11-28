"use client"

import * as React from "react"
import { useHealthCheck } from "@/hooks/use-health-check"
import { useReadiness } from "@/hooks/use-readiness"
import { StatusIndicator } from "@/components/ui/status-indicator"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { ShieldAlert, ShieldCheck, RefreshCw, Server, Database } from "lucide-react"
import type { InfrastructureReadiness } from "@/types"

const INFRASTRUCTURE_DEPENDENCIES: ReadonlyArray<{
  key: keyof InfrastructureReadiness
  label: string
}> = [
  { key: "postgres", label: "PostgreSQL" },
  { key: "redis", label: "Redis" },
  { key: "qdrant", label: "Qdrant" },
  { key: "kafka", label: "Kafka" },
]

export function HealthCheck() {
  const { status: livenessStatus, isRetrying: isLivenessRetrying, retry: retryLiveness } = useHealthCheck()
  const { state: readinessState, data: readinessData, isRetrying: isReadinessRetrying, retry: retryReadiness } = useReadiness()

  const isRetrying = isLivenessRetrying || isReadinessRetrying

  const handleRetryAll = () => {
    retryLiveness()
    retryReadiness()
  }

  const getReadinessIndicatorStatus = (): "online" | "warning" | "offline" | "loading" => {
    if (readinessState === "loading") return "loading"
    if (readinessState === "ready") return "online"
    if (readinessState === "degraded") return "warning"
    return "offline"
  }

  const getReadinessLabel = () => {
    switch (readinessState) {
      case "ready":
        return "READY"
      case "degraded":
        return "DEGRADED / NOT READY"
      case "unavailable":
        return "UNAVAILABLE"
      case "loading":
      default:
        return "CHECKING..."
    }
  }

  return (
    <Card className="w-full max-w-md">
      <CardContent className="space-y-4 p-5">
        {/* Header / Actions */}
        <div className="flex items-center justify-between border-b pb-3">
          <div className="flex items-center space-x-2">
            <Server className="h-4 w-4 text-primary" />
            <span className="text-sm font-semibold tracking-tight">System Status</span>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleRetryAll}
            disabled={isRetrying}
            className="h-8 px-2 text-xs text-muted-foreground hover:text-foreground"
          >
            <RefreshCw className={`mr-1 h-3.5 w-3.5 ${isRetrying ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>

        {/* 1. Liveness Status (GET /health) */}
        <div className="flex items-center justify-between rounded-md border bg-muted/20 p-3">
          <div className="flex items-center space-x-3">
            <div className={`rounded-full p-1.5 ${livenessStatus === "connected" ? "bg-green-500/10 text-green-500" : "bg-red-500/10 text-red-500"}`}>
              {livenessStatus === "connected" ? (
                <ShieldCheck className="h-4 w-4" />
              ) : (
                <ShieldAlert className="h-4 w-4" />
              )}
            </div>
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Liveness</p>
              <p className="text-sm font-medium">
                {livenessStatus === "connected" ? "Backend Connected" : livenessStatus === "loading" ? "Checking process..." : "Backend Unavailable"}
              </p>
            </div>
          </div>
          <StatusIndicator status={livenessStatus === "connected" ? "online" : livenessStatus === "loading" ? "loading" : "offline"} />
        </div>

        {/* 2. Readiness Status (GET /ready) */}
        <div className="rounded-md border bg-muted/20 p-3 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className={`rounded-full p-1.5 ${readinessState === "ready" ? "bg-green-500/10 text-green-500" : readinessState === "degraded" ? "bg-yellow-500/10 text-yellow-500" : "bg-red-500/10 text-red-500"}`}>
                {readinessState === "ready" ? (
                  <ShieldCheck className="h-4 w-4" />
                ) : (
                  <ShieldAlert className="h-4 w-4" />
                )}
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Readiness</p>
                <p className="text-sm font-medium">{getReadinessLabel()}</p>
              </div>
            </div>
            <StatusIndicator status={getReadinessIndicatorStatus()} />
          </div>

          {/* Infrastructure Breakdown */}
          <div className="border-t pt-2.5">
            <p className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1.5">
              <Database className="h-3.5 w-3.5" />
              Infrastructure Dependencies
            </p>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {INFRASTRUCTURE_DEPENDENCIES.map(({ key, label }) => {
                const serviceReady = readinessData ? readinessData[key] : undefined
                const dotClass =
                  serviceReady === true
                    ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]"
                    : serviceReady === false
                      ? "bg-rose-500"
                      : "bg-slate-500"
                const textClass =
                  serviceReady === true
                    ? "text-emerald-400"
                    : serviceReady === false
                      ? "text-rose-400"
                      : "text-muted-foreground"
                const statusLabel =
                  serviceReady === true
                    ? "Ready"
                    : serviceReady === false
                      ? "Not Ready"
                      : readinessState === "loading"
                        ? "Checking..."
                        : "Unknown"

                return (
                  <div
                    key={key}
                    className="flex items-center justify-between rounded-md bg-background/60 px-3 py-2 border border-border/80"
                  >
                    <div className="flex items-center gap-2">
                      <span className={`h-2 w-2 rounded-full ${dotClass}`} />
                      <span className="font-medium text-foreground">{label}</span>
                    </div>
                    <span className={`font-semibold ${textClass}`}>{statusLabel}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
