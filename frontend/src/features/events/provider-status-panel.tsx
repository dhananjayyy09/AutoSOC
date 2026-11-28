"use client"

import * as React from "react"
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Info,
  PauseCircle,
  ServerOff,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { EmptyState } from "@/components/ui/empty-state"
import { ErrorState } from "@/components/ui/error-state"
import { LoadingState } from "@/components/ui/loading-state"
import { sanitizeFailureCategory } from "@/lib/api"
import { cn } from "@/lib/utils"
import type { ThreatIntelProviderStatus } from "@/types"

interface ProviderStatusPanelProps {
  providers?: ThreatIntelProviderStatus[] | null
  isLoading?: boolean
  error?: string | null
  onRetry?: () => void
  backendSupported?: boolean
}

function getProviderHealthPresentation(provider: ThreatIntelProviderStatus) {
  if (!provider.enabled || provider.status.trim().toLowerCase() === "disabled") {
    return {
      label: "Disabled",
      className: "border-slate-500/40 bg-slate-500/10 text-slate-300",
      Icon: PauseCircle,
    }
  }

  switch (provider.status.trim().toLowerCase()) {
    case "healthy":
    case "ok":
    case "available":
      return {
        label: "Healthy",
        className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
        Icon: CheckCircle2,
      }
    case "degraded":
    case "rate_limited":
      return {
        label: "Degraded",
        className: "border-amber-500/40 bg-amber-500/10 text-amber-300",
        Icon: AlertTriangle,
      }
    case "unavailable":
    case "down":
    case "circuit_open":
      return {
        label: "Unavailable",
        className: "border-red-500/40 bg-red-500/10 text-red-300",
        Icon: ServerOff,
      }
    default:
      return {
        label: provider.status,
        className: "border-slate-500/40 bg-slate-500/10 text-slate-300",
        Icon: Activity,
      }
  }
}

function getCircuitPresentation(circuitState: string | null | undefined) {
  const normalized = typeof circuitState === "string" ? circuitState.trim().toLowerCase() : ""
  if (!normalized) return null

  switch (normalized) {
    case "closed":
      return {
        label: "Circuit Closed",
        className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
        Icon: ShieldCheck,
      }
    case "half_open":
    case "half-open":
      return {
        label: "Circuit Half-Open",
        className: "border-amber-500/40 bg-amber-500/10 text-amber-300",
        Icon: AlertTriangle,
      }
    case "open":
      return {
        label: "Circuit Open",
        className: "border-red-500/40 bg-red-500/10 text-red-300",
        Icon: ShieldAlert,
      }
    default:
      return {
        label: `Circuit ${circuitState}`,
        className: "border-slate-500/40 bg-slate-500/10 text-slate-300",
        Icon: Activity,
      }
  }
}

export function ProviderStatusPanel({
  providers,
  isLoading = false,
  error = null,
  onRetry,
  backendSupported,
}: ProviderStatusPanelProps) {
  const isEndpointAvailable =
    backendSupported ?? (providers !== undefined || isLoading || Boolean(error))

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="h-4 w-4 text-primary" aria-hidden="true" />
              Threat Intelligence Provider Status
            </CardTitle>
            <CardDescription>
              Operational readiness, circuit-breaker state, and sanitized failure telemetry for configured TI providers.
            </CardDescription>
          </div>
          {Array.isArray(providers) && providers.length > 0 && (
            <Badge variant="outline" className="font-mono text-xs">
              {providers.length} configured
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {isLoading && (
          <LoadingState text="Checking TI provider operational status..." className="h-[140px]" />
        )}

        {!isLoading && error && (
          <ErrorState
            title="Unable to load TI provider status"
            description={error}
            onRetry={onRetry}
            className="h-[140px]"
          />
        )}

        {!isLoading && !error && !isEndpointAvailable && (
          <div
            role="status"
            aria-label="Provider status telemetry notice"
            className="flex items-start gap-2.5 rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground"
          >
            <Info className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
            <div className="space-y-0.5">
              <p className="font-medium text-foreground">
                Global provider-status endpoint not exposed by backend
              </p>
              <p>
                Provider readiness telemetry will appear here once the backend exposes a provider-status API. Per-observable lookup states and failure outcomes are shown in event enrichment details below.
              </p>
            </div>
          </div>
        )}

        {!isLoading && !error && isEndpointAvailable && (!providers || providers.length === 0) && (
          <EmptyState
            title="No TI providers reported"
            description="No threat intelligence providers were returned by the backend."
            className="h-[140px]"
          />
        )}

        {!isLoading && !error && providers && providers.length > 0 && (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {providers.map((provider) => {
              const health = getProviderHealthPresentation(provider)
              const circuit = getCircuitPresentation(provider.circuit_breaker_state)
              const safeFailure = sanitizeFailureCategory(provider.failure_category)

              return (
                <div
                  key={provider.provider_id}
                  aria-label={`Provider status for ${provider.provider_name || provider.provider_id}`}
                  className="space-y-2 rounded-md border bg-muted/20 p-3 text-xs"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="space-y-0.5">
                      <p className="font-semibold text-foreground">
                        {provider.provider_name || provider.provider_id}
                      </p>
                      <p className="font-mono text-[11px] text-muted-foreground">
                        {provider.provider_id}
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge
                        variant="outline"
                        className={cn(
                          "inline-flex items-center gap-1 text-[11px]",
                          health.className
                        )}
                      >
                        <health.Icon className="h-3 w-3 shrink-0" aria-hidden="true" />
                        <span>{health.label}</span>
                      </Badge>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge variant="outline" className="text-[11px]">
                      {provider.enabled ? "Enabled" : "Disabled"}
                    </Badge>
                    {typeof provider.is_live === "boolean" && (
                      <Badge variant="outline" className="text-[11px]">
                        {provider.is_live ? "Live TI" : "Fixture / Deterministic"}
                      </Badge>
                    )}
                    {circuit && (
                      <Badge
                        variant="outline"
                        className={cn(
                          "inline-flex items-center gap-1 text-[11px]",
                          circuit.className
                        )}
                      >
                        <circuit.Icon className="h-3 w-3 shrink-0" aria-hidden="true" />
                        <span>{circuit.label}</span>
                      </Badge>
                    )}
                    {provider.retry_exhausted && (
                      <Badge
                        variant="outline"
                        className="border-red-500/40 bg-red-500/10 text-[11px] text-red-300"
                      >
                        Retry Exhausted
                      </Badge>
                    )}
                  </div>

                  <dl className="space-y-1 text-[11px] text-muted-foreground">
                    <div className="flex items-center justify-between gap-2">
                      <dt>Last Successful Lookup</dt>
                      <dd className="font-mono text-foreground">
                        {provider.last_success_at || "—"}
                      </dd>
                    </div>
                    {typeof provider.retry_count === "number" && (
                      <div className="flex items-center justify-between gap-2">
                        <dt>Retry Attempts</dt>
                        <dd className="font-mono text-foreground">{provider.retry_count}</dd>
                      </div>
                    )}
                    {safeFailure && (
                      <div className="space-y-0.5 pt-0.5">
                        <dt>Failure Category</dt>
                        <dd className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 font-mono text-amber-300">
                          {safeFailure}
                        </dd>
                      </div>
                    )}
                  </dl>
                </div>
              )
            })}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
