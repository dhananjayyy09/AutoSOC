"use client"

import * as React from "react"
import { useHealthCheck } from "@/hooks/use-health-check"
import { useReadiness } from "@/hooks/use-readiness"
import { StatusIndicator } from "@/components/ui/status-indicator"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { ShieldAlert, ShieldCheck, RefreshCw, Server, Database } from "lucide-react"

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
              <div className="flex items-center justify-between rounded-md bg-background/60 px-3 py-2 border border-border/80">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${readinessData?.postgres ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]" : "bg-rose-500"}`} />
                  <span className="font-medium text-foreground">PostgreSQL</span>
                </div>
                <span className={`font-semibold ${readinessData?.postgres ? "text-emerald-400" : "text-rose-400"}`}>
                  {readinessData?.postgres ? "Ready" : "Not Ready"}
                </span>
              </div>
              <div className="flex items-center justify-between rounded-md bg-background/60 px-3 py-2 border border-border/80">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${readinessData?.redis ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]" : "bg-rose-500"}`} />
                  <span className="font-medium text-foreground">Redis</span>
                </div>
                <span className={`font-semibold ${readinessData?.redis ? "text-emerald-400" : "text-rose-400"}`}>
                  {readinessData?.redis ? "Ready" : "Not Ready"}
                </span>
              </div>
              <div className="flex items-center justify-between rounded-md bg-background/60 px-3 py-2 border border-border/80">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${readinessData?.qdrant ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]" : "bg-rose-500"}`} />
                  <span className="font-medium text-foreground">Qdrant</span>
                </div>
                <span className={`font-semibold ${readinessData?.qdrant ? "text-emerald-400" : "text-rose-400"}`}>
                  {readinessData?.qdrant ? "Ready" : "Not Ready"}
                </span>
              </div>
              <div className="flex items-center justify-between rounded-md bg-background/60 px-3 py-2 border border-border/80">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${readinessData?.kafka ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]" : "bg-rose-500"}`} />
                  <span className="font-medium text-foreground">Kafka</span>
                </div>
                <span className={`font-semibold ${readinessData?.kafka ? "text-emerald-400" : "text-rose-400"}`}>
                  {readinessData?.kafka ? "Ready" : "Not Ready"}
                </span>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
