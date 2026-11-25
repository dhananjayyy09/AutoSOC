"use client"

import * as React from "react"
import { RefreshCw } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { LoadingState } from "@/components/ui/loading-state"
import { ErrorState } from "@/components/ui/error-state"
import { EmptyState } from "@/components/ui/empty-state"
import { useApiRequest } from "@/hooks/use-api-request"
import { DEFAULT_RECENT_EVENTS_LIMIT, fetchRecentEvents } from "@/lib/api"
import type { IngestedEventRecord } from "@/types"

interface RecentEventsListProps {
  refreshTrigger?: number
  limit?: number
}

export function RecentEventsList({
  refreshTrigger = 0,
  limit = DEFAULT_RECENT_EVENTS_LIMIT,
}: RecentEventsListProps) {
  const fetcher = React.useCallback(() => fetchRecentEvents(limit), [limit])
  const { status, data, error, execute } = useApiRequest<IngestedEventRecord[]>(fetcher)

  React.useEffect(() => {
    void execute()
  }, [execute, refreshTrigger])

  const isLoading = status === "loading" || status === "idle"
  const events = data ?? []

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-4 space-y-0">
        <div className="space-y-1">
          <CardTitle className="text-lg">Recent Ingestions</CardTitle>
          <CardDescription>
            Showing up to {limit} recent records returned by the backend.
          </CardDescription>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => void execute()}
          disabled={status === "loading"}
          aria-label="Refresh recent events"
        >
          <RefreshCw
            className={`mr-2 h-3.5 w-3.5 ${status === "loading" ? "animate-spin" : ""}`}
            aria-hidden="true"
          />
          Refresh
        </Button>
      </CardHeader>
      <CardContent>
        {isLoading && data === null && (
          <LoadingState text="Loading recent ingested events..." className="h-[280px]" />
        )}

        {status === "error" && (
          <ErrorState
            title="Unable to Load Recent Events"
            description={error ?? "Could not retrieve ingested events from the backend."}
            onRetry={() => void execute()}
            className="h-[280px]"
          />
        )}

        {status === "success" && events.length === 0 && (
          <EmptyState
            title="No ingested events yet"
            description="No security events have been returned by the backend ingestion store."
            className="h-[280px]"
          />
        )}

        {events.length > 0 && (
          <Table aria-label="Recent ingested security events">
            <TableHeader>
              <TableRow>
                <TableHead>Ingestion ID</TableHead>
                <TableHead>Event ID</TableHead>
                <TableHead>Source / Type</TableHead>
                <TableHead>Timestamp</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.map((evt) => {
                const sourceLabel = evt.source || evt.source_type
                const sourceAndType = [sourceLabel, evt.event_type || evt.sensor_id].filter(Boolean).join(" / ") || "—"
                const timestampLabel = evt.ingest_time || evt.timestamp || evt.received_at || "—"

                return (
                  <TableRow key={evt.ingestion_id}>
                    <TableCell className="font-mono text-xs">{evt.ingestion_id}</TableCell>
                    <TableCell className="font-mono text-xs">{evt.event_id || "—"}</TableCell>
                    <TableCell className="text-xs">{sourceAndType}</TableCell>
                    <TableCell className="font-mono text-xs">{timestampLabel}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Badge variant="outline">{evt.status}</Badge>
                        {evt.possible_duplicate && (
                          <Badge variant="outline" className="border-amber-500/40 text-amber-300">
                            duplicate
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}
