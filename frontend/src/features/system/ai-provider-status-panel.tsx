"use client"

import * as React from "react"
import {
  AlertCircle,
  CheckCircle2,
  Cpu,
  Info,
  PauseCircle,
  RefreshCw,
  ServerOff,
  Settings2,
} from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ErrorState } from "@/components/ui/error-state"
import { LoadingState } from "@/components/ui/loading-state"
import { StatusIndicator } from "@/components/ui/status-indicator"
import { useApiRequest } from "@/hooks/use-api-request"
import { AI_PROVIDER_STATUS_ENDPOINT, fetchAiProviderStatus } from "@/lib/api"
import { cn } from "@/lib/utils"
import type { AiProviderOperationalState, AiProviderStatusResult } from "@/types"

interface AiProviderStatusPanelProps {
  /** Whether to perform an initial fetch automatically on mount. No background polling is used. */
  autoFetch?: boolean
  /** Optional override endpoint path once backend route is confirmed. */
  endpoint?: string
  /** Optional custom fetcher for isolated testing or alternative transport. */
  fetcher?: () => Promise<AiProviderStatusResult>
}

interface StatePresentation {
  label: string
  indicator: "online" | "warning" | "offline" | "loading"
  badgeClass: string
  description: string
  Icon: React.ComponentType<{ className?: string }>
}

const STATE_PRESENTATION: Record<AiProviderOperationalState, StatePresentation> = {
  ready: {
    label: "Ready",
    indicator: "online",
    badgeClass: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
    description:
      "AI provider reachable for infrastructure readiness checks. This does not indicate active event analysis or autonomous agent execution.",
    Icon: CheckCircle2,
  },
  disabled: {
    label: "Disabled",
    indicator: "offline",
    badgeClass: "border-slate-500/40 bg-slate-500/10 text-slate-300",
    description: "AI provider integration is disabled in backend configuration.",
    Icon: PauseCircle,
  },
  unconfigured: {
    label: "Unconfigured",
    indicator: "offline",
    badgeClass: "border-slate-500/40 bg-slate-500/10 text-slate-300",
    description: "No AI provider or model is configured on the backend.",
    Icon: Settings2,
  },
  unavailable: {
    label: "Unavailable",
    indicator: "warning",
    badgeClass: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    description: "Configured AI provider could not be reached or is currently degraded.",
    Icon: ServerOff,
  },
  error: {
    label: "Error",
    indicator: "offline",
    badgeClass: "border-red-500/40 bg-red-500/10 text-red-300",
    description: "Backend health check reported an AI provider operational error.",
    Icon: AlertCircle,
  },
}

export function AiProviderStatusPanel({
  autoFetch = true,
  endpoint = AI_PROVIDER_STATUS_ENDPOINT,
  fetcher,
}: AiProviderStatusPanelProps) {
  const requestFn = React.useCallback(
    () => (fetcher ? fetcher() : fetchAiProviderStatus(endpoint)),
    [fetcher, endpoint]
  )

  const { status, data, error, execute } = useApiRequest<AiProviderStatusResult>(requestFn)

  React.useEffect(() => {
    if (autoFetch) {
      void execute()
    }
  }, [autoFetch, execute])

  const isLoading = status === "loading"
  const providerData = data?.supported ? data.data : undefined
  const presentation = providerData ? STATE_PRESENTATION[providerData.status] : null

  return (
    <Card className="w-full" aria-label="AI provider status">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <Cpu className="h-4 w-4 text-primary" aria-hidden="true" />
              AI Provider Status
            </CardTitle>
            <CardDescription className="text-xs">
              Infrastructure connectivity status for the configured LLM provider. Connectivity does not imply automated event analysis.
            </CardDescription>
          </div>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => void execute()}
            disabled={isLoading}
            aria-label="Refresh AI provider status"
            className="h-8 shrink-0 px-2 text-xs text-muted-foreground hover:text-foreground"
          >
            <RefreshCw
              className={cn("mr-1 h-3.5 w-3.5", isLoading && "animate-spin")}
              aria-hidden="true"
            />
            {isLoading ? "Checking..." : "Refresh"}
          </Button>
        </div>
      </CardHeader>

      <CardContent>
        {status === "idle" && (
          <div
            role="status"
            aria-label="AI provider status not checked"
            className="flex items-center justify-between gap-3 rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground"
          >
            <span>AI provider readiness has not been checked in this session.</span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => void execute()}
              className="h-7 shrink-0 text-xs"
            >
              Check Status
            </Button>
          </div>
        )}

        {isLoading && (
          <LoadingState text="Checking AI provider status..." className="h-[140px]" />
        )}

        {status === "error" && (
          <ErrorState
            title="Unable to check AI provider status"
            description={error ?? "An unexpected error occurred while checking AI provider status."}
            onRetry={() => void execute()}
            isRetrying={isLoading}
            className="h-[140px]"
          />
        )}

        {status === "success" && data && !data.supported && (
          <div
            role="status"
            aria-label="AI provider status unsupported"
            className="flex items-start gap-2.5 rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground"
          >
            <Info className="mt-0.5 h-4 w-4 shrink-0 text-primary" aria-hidden="true" />
            <div className="space-y-0.5">
              <p className="font-medium text-foreground">
                AI provider status endpoint not exposed by backend
              </p>
              <p>
                Operational status will appear here once the Day 12 backend provider-status route is available.
              </p>
            </div>
          </div>
        )}

        {status === "success" && data?.supported && providerData && presentation && (
          <div
            role="status"
            aria-label={`AI provider operational state: ${presentation.label}`}
            className="space-y-3 rounded-md border bg-muted/20 p-3 text-xs"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Badge
                  variant="outline"
                  className={cn(
                    "inline-flex items-center gap-1 text-[11px]",
                    presentation.badgeClass
                  )}
                >
                  <presentation.Icon className="h-3 w-3 shrink-0" aria-hidden="true" />
                  <span>{presentation.label}</span>
                </Badge>
                {providerData.provider && (
                  <span className="font-medium text-foreground">{providerData.provider}</span>
                )}
              </div>
              <StatusIndicator status={presentation.indicator} />
            </div>

            <p className="text-muted-foreground">{presentation.description}</p>

            <dl className="grid grid-cols-1 gap-1.5 border-t pt-2.5 sm:grid-cols-2">
              <div className="flex items-center justify-between gap-2 rounded bg-background/60 px-2.5 py-1.5 border border-border/60">
                <dt className="text-muted-foreground">Provider</dt>
                <dd className="font-mono text-foreground">{providerData.provider || "—"}</dd>
              </div>
              <div className="flex items-center justify-between gap-2 rounded bg-background/60 px-2.5 py-1.5 border border-border/60">
                <dt className="text-muted-foreground">Configured Model</dt>
                <dd className="font-mono text-foreground">{providerData.model || "—"}</dd>
              </div>
              <div className="flex items-center justify-between gap-2 rounded bg-background/60 px-2.5 py-1.5 border border-border/60 sm:col-span-2">
                <dt className="text-muted-foreground">Last Status Check</dt>
                <dd className="font-mono text-foreground">{providerData.checked_at || "—"}</dd>
              </div>
              {providerData.message && (
                <div className="space-y-0.5 rounded bg-background/60 px-2.5 py-1.5 border border-border/60 sm:col-span-2">
                  <dt className="text-muted-foreground">Status Message</dt>
                  <dd className="font-mono text-foreground">{providerData.message}</dd>
                </div>
              )}
            </dl>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
