"use client"

import * as React from "react"
import { ChevronLeft, ChevronRight, Eye, FilterX, RefreshCw, Search } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { SeverityBadge } from "@/components/ui/severity-badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { LoadingState } from "@/components/ui/loading-state"
import { ErrorState } from "@/components/ui/error-state"
import { EmptyState } from "@/components/ui/empty-state"
import { NormalizationStatusBadge } from "./normalization-status-badge"
import { EnrichmentStatusBadge } from "./enrichment-status-badge"
import {
  ApiError,
  DEFAULT_RECENT_EVENTS_LIMIT,
  MAX_QUERY_OFFSET,
  isNetworkError,
  queryNormalizedEvents,
} from "@/lib/api"
import type {
  EventCategory,
  NormalizedEventListResult,
  NormalizedEventSortField,
  NormalizedEventsQueryParams,
  NormalizedSecurityEvent,
  SecurityEventSource,
  SeverityLevel,
} from "@/types"

interface NormalizedEventExplorerProps {
  refreshTrigger?: number
  selectedEventKey?: string | null
  onSelectNormalizedEvent?: (event: NormalizedSecurityEvent) => void
}

interface FilterState {
  appliedSearch: string
  appliedEventType: string
  source_type: string
  normalization_status: string
  event_category: string
  severity: string
  start_time: string
  end_time: string
  sort_by: NormalizedEventSortField
  sort_order: "asc" | "desc"
  limit: number
  offset: number
}

const EVENT_TYPE_REGEX = /^[a-z0-9_]+(\.[a-z0-9_]+)*$/

const DEFAULT_FILTERS: FilterState = {
  appliedSearch: "",
  appliedEventType: "",
  source_type: "",
  normalization_status: "",
  event_category: "",
  severity: "",
  start_time: "",
  end_time: "",
  sort_by: "created_at",
  sort_order: "desc",
  limit: DEFAULT_RECENT_EVENTS_LIMIT,
  offset: 0,
}

const SOURCE_OPTIONS: { value: SecurityEventSource; label: string }[] = [
  { value: "sysmon", label: "Sysmon" },
  { value: "zeek", label: "Zeek" },
  { value: "suricata", label: "Suricata" },
  { value: "windows_event_log", label: "Windows Event Log" },
  { value: "auditd", label: "Auditd" },
  { value: "osquery", label: "Osquery" },
  { value: "custom", label: "Custom" },
]

const STATUS_OPTIONS = [
  { value: "normalized", label: "Normalized" },
  { value: "normalized_with_warnings", label: "Normalized with Warnings" },
  { value: "failed", label: "Normalization Failed" },
  { value: "unsupported", label: "Unsupported Source" },
]

const CATEGORY_OPTIONS: { value: EventCategory; label: string }[] = [
  { value: "process", label: "Process" },
  { value: "network", label: "Network" },
  { value: "file", label: "File" },
  { value: "registry", label: "Registry" },
  { value: "auth", label: "Auth" },
  { value: "alert", label: "Alert" },
  { value: "unknown", label: "Unknown" },
]

const SEVERITY_OPTIONS = [
  { value: "1", label: "1 - INFO" },
  { value: "2", label: "2 - LOW" },
  { value: "3", label: "3 - MEDIUM" },
  { value: "4", label: "4 - HIGH" },
  { value: "5", label: "5 - CRITICAL" },
]

function mapNumericSeverity(severity: number | null | undefined): SeverityLevel | null {
  switch (severity) {
    case 1:
      return "INFO"
    case 2:
      return "LOW"
    case 3:
      return "MEDIUM"
    case 4:
      return "HIGH"
    case 5:
      return "CRITICAL"
    default:
      return null
  }
}

export function getNormalizedEventKey(evt: NormalizedSecurityEvent): string {
  return evt.event_id ?? `ing:${evt.ingestion_id}`
}

export function NormalizedEventExplorer({
  refreshTrigger = 0,
  selectedEventKey = null,
  onSelectNormalizedEvent,
}: NormalizedEventExplorerProps) {
  const [searchInput, setSearchInput] = React.useState("")
  const [eventTypeInput, setEventTypeInput] = React.useState("")
  const [startLocalInput, setStartLocalInput] = React.useState("")
  const [endLocalInput, setEndLocalInput] = React.useState("")
  const [filterValidationError, setFilterValidationError] = React.useState<string | null>(null)
  const [filters, setFilters] = React.useState<FilterState>(DEFAULT_FILTERS)
  const [result, setResult] = React.useState<NormalizedEventListResult | null>(null)
  const [isLoading, setIsLoading] = React.useState(true)
  const [error, setError] = React.useState<string | null>(null)
  const [localRefreshTick, setLocalRefreshTick] = React.useState(0)
  const requestCounterRef = React.useRef(0)

  const hasActiveFilters = Boolean(
    filters.appliedSearch ||
      filters.appliedEventType ||
      filters.source_type ||
      filters.normalization_status ||
      filters.event_category ||
      filters.severity ||
      filters.start_time ||
      filters.end_time ||
      filters.sort_by !== DEFAULT_FILTERS.sort_by ||
      filters.sort_order !== DEFAULT_FILTERS.sort_order ||
      filters.offset > 0
  )

  const buildApiParams = React.useCallback((state: FilterState): NormalizedEventsQueryParams => {
    const parsedSeverity = state.severity ? Number(state.severity) : undefined
    return {
      limit: state.limit,
      offset: state.offset,
      search: state.appliedSearch || undefined,
      event_type: state.appliedEventType || undefined,
      source_type: state.source_type || undefined,
      normalization_status: state.normalization_status || undefined,
      event_category: state.event_category || undefined,
      severity:
        parsedSeverity && parsedSeverity >= 1 && parsedSeverity <= 5
          ? parsedSeverity
          : undefined,
      start_time: state.start_time || undefined,
      end_time: state.end_time || undefined,
      sort_by: state.sort_by,
      sort_order: state.sort_order,
    }
  }, [])

  React.useEffect(() => {
    const requestId = ++requestCounterRef.current
    const params = buildApiParams(filters)

    queryNormalizedEvents(params)
      .then((res) => {
        if (requestCounterRef.current !== requestId) return
        setResult(res)
        setError(null)
      })
      .catch((err) => {
        if (requestCounterRef.current !== requestId) return
        if (err instanceof ApiError) {
          setError(err.userMessage)
        } else if (isNetworkError(err)) {
          setError("Unable to reach the backend event explorer endpoint.")
        } else {
          setError("Unable to load normalized events.")
        }
      })
      .finally(() => {
        if (requestCounterRef.current === requestId) {
          setIsLoading(false)
        }
      })
  }, [filters, refreshTrigger, localRefreshTick, buildApiParams])

  const handleRefresh = () => {
    setIsLoading(true)
    setError(null)
    setLocalRefreshTick((t) => t + 1)
  }

  const toUtcIsoOrNull = (localValue: string): string | null => {
    const trimmed = localValue.trim()
    if (!trimmed) return null
    const parsed = new Date(trimmed)
    if (Number.isNaN(parsed.getTime())) return null
    return parsed.toISOString()
  }

  const handleSearchSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setFilterValidationError(null)

    const cleanedEventType = eventTypeInput.trim().toLowerCase()
    if (cleanedEventType && !EVENT_TYPE_REGEX.test(cleanedEventType)) {
      setFilterValidationError(
        "Event Type must use lowercase dot-notation (e.g. alert.ids or process.create)."
      )
      return
    }

    const startIso = toUtcIsoOrNull(startLocalInput)
    if (startLocalInput.trim() && !startIso) {
      setFilterValidationError("Start time must be a valid date/time.")
      return
    }

    const endIso = toUtcIsoOrNull(endLocalInput)
    if (endLocalInput.trim() && !endIso) {
      setFilterValidationError("End time must be a valid date/time.")
      return
    }

    if (startIso && endIso && startIso > endIso) {
      setFilterValidationError("Start time must be earlier than or equal to End time.")
      return
    }

    setIsLoading(true)
    setError(null)
    setFilters((prev) => ({
      ...prev,
      appliedSearch: searchInput.trim(),
      appliedEventType: cleanedEventType,
      start_time: startIso ?? "",
      end_time: endIso ?? "",
      offset: 0,
    }))
  }

  const handleClearFilters = () => {
    setSearchInput("")
    setEventTypeInput("")
    setStartLocalInput("")
    setEndLocalInput("")
    setFilterValidationError(null)
    setIsLoading(true)
    setError(null)
    setFilters(DEFAULT_FILTERS)
  }

  const handleFilterChange = <K extends keyof FilterState>(key: K, value: FilterState[K]) => {
    setFilterValidationError(null)
    setIsLoading(true)
    setError(null)
    setFilters((prev) => ({
      ...prev,
      [key]: value,
      offset: key === "offset" ? (value as number) : 0,
    }))
  }

  const items = result?.items ?? []
  const count = result?.count ?? items.length
  const total = result?.total
  const currentPage = Math.floor(filters.offset / filters.limit) + 1
  const canPrev = filters.offset > 0 && !isLoading
  const canNext =
    !isLoading &&
    Boolean(result?.has_more) &&
    filters.offset + filters.limit <= MAX_QUERY_OFFSET

  const selectClass =
    "h-9 rounded-md border border-input bg-background px-2.5 text-xs text-foreground shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"

  return (
    <Card>
      <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="space-y-1">
          <CardTitle className="text-lg">Normalized Event Explorer</CardTitle>
          <CardDescription>
            Search, filter, sort, and inspect normalized security events persisted in PostgreSQL.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleClearFilters}
            disabled={
              !hasActiveFilters &&
              !searchInput &&
              !eventTypeInput &&
              !startLocalInput &&
              !endLocalInput
            }
          >
            <FilterX className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            Clear Filters
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={isLoading}
            aria-label="Refresh normalized events"
          >
            <RefreshCw
              className={`mr-1.5 h-3.5 w-3.5 ${isLoading ? "animate-spin" : ""}`}
              aria-hidden="true"
            />
            Refresh
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Search & Filter Controls */}
        <div className="space-y-3 rounded-md border bg-muted/20 p-3">
          <form onSubmit={handleSearchSubmit} className="space-y-2">
            <div className="flex flex-col gap-2 sm:flex-row">
              <div className="relative flex-1">
                <Search
                  className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground"
                  aria-hidden="true"
                />
                <input
                  type="search"
                  aria-label="Search normalized events"
                  placeholder="Search host, IP, event type, process, domain, or ID..."
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  className="h-9 w-full rounded-md border border-input bg-background pl-9 pr-3 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                />
              </div>
              <input
                type="text"
                aria-label="Filter by event type"
                placeholder="Event type (e.g. alert.ids)"
                value={eventTypeInput}
                onChange={(e) => setEventTypeInput(e.target.value)}
                className="h-9 rounded-md border border-input bg-background px-3 text-xs shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring sm:w-48"
              />
              <Button type="submit" size="sm" disabled={isLoading}>
                Search
              </Button>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <label htmlFor="explorer-start-time">From (UTC/local):</label>
              <input
                id="explorer-start-time"
                type="datetime-local"
                aria-label="Start time"
                value={startLocalInput}
                onChange={(e) => setStartLocalInput(e.target.value)}
                className={selectClass}
              />
              <label htmlFor="explorer-end-time">To:</label>
              <input
                id="explorer-end-time"
                type="datetime-local"
                aria-label="End time"
                value={endLocalInput}
                onChange={(e) => setEndLocalInput(e.target.value)}
                className={selectClass}
              />
            </div>
            {filterValidationError && (
              <p role="alert" className="text-xs text-destructive">
                {filterValidationError}
              </p>
            )}
          </form>

          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-6">
            <select
              aria-label="Filter by source type"
              value={filters.source_type}
              onChange={(e) => handleFilterChange("source_type", e.target.value)}
              className={selectClass}
            >
              <option value="">All Sources</option>
              {SOURCE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>

            <select
              aria-label="Filter by normalization status"
              value={filters.normalization_status}
              onChange={(e) => handleFilterChange("normalization_status", e.target.value)}
              className={selectClass}
            >
              <option value="">All Norm. Statuses</option>
              {STATUS_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>

            <select
              aria-label="Filter by event category"
              value={filters.event_category}
              onChange={(e) => handleFilterChange("event_category", e.target.value)}
              className={selectClass}
            >
              <option value="">All Categories</option>
              {CATEGORY_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>

            <select
              aria-label="Filter by severity"
              value={filters.severity}
              onChange={(e) => handleFilterChange("severity", e.target.value)}
              className={selectClass}
            >
              <option value="">All Severities</option>
              {SEVERITY_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>

            <select
              aria-label="Sort normalized events by"
              value={filters.sort_by}
              onChange={(e) =>
                handleFilterChange("sort_by", e.target.value as FilterState["sort_by"])
              }
              className={selectClass}
            >
              <option value="created_at">Sort: Created At</option>
              <option value="timestamp">Sort: Event Time</option>
              <option value="severity">Sort: Severity</option>
              <option value="source_type">Sort: Source Type</option>
              <option value="event_category">Sort: Category</option>
              <option value="normalization_status">Sort: Norm. Status</option>
            </select>

            <select
              aria-label="Sort order"
              value={filters.sort_order}
              onChange={(e) =>
                handleFilterChange("sort_order", e.target.value as FilterState["sort_order"])
              }
              className={selectClass}
            >
              <option value="desc">Order: Newest / High First</option>
              <option value="asc">Order: Oldest / Low First</option>
            </select>
          </div>
        </div>

        {/* Result Count & Page Size */}
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
          <div aria-live="polite">
            {result ? (
              <span>
                Showing <strong className="text-foreground">{count}</strong>{" "}
                {count === 1 ? "event" : "events"}
                {typeof total === "number" ? (
                  <>
                    {" "}
                    of <strong className="text-foreground">{total}</strong> total
                  </>
                ) : null}
                {" · "}Page {currentPage}
              </span>
            ) : (
              <span>Querying normalized events...</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <label htmlFor="explorer-page-size">Per page:</label>
            <select
              id="explorer-page-size"
              aria-label="Results per page"
              value={filters.limit}
              onChange={(e) => handleFilterChange("limit", Number(e.target.value))}
              className={selectClass}
            >
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={50}>50</option>
            </select>
          </div>
        </div>

        {/* Content Area */}
        {isLoading && result === null && (
          <LoadingState text="Querying normalized security events..." className="h-[260px]" />
        )}

        {!isLoading && error && (
          <ErrorState
            title="Unable to Query Normalized Events"
            description={error}
            onRetry={handleRefresh}
            className="h-[260px]"
          />
        )}

        {!isLoading && !error && items.length === 0 && hasActiveFilters && (
          <EmptyState
            title="No matching normalized events"
            description="No normalized events matched your current search or filter criteria."
            actionLabel="Clear Filters"
            onAction={handleClearFilters}
            className="h-[260px]"
          />
        )}

        {!isLoading && !error && items.length === 0 && !hasActiveFilters && (
          <EmptyState
            title="No normalized events yet"
            description="Submit a security event envelope above to persist and normalize it."
            className="h-[260px]"
          />
        )}

        {!error && items.length > 0 && (
          <Table aria-label="Normalized security events explorer">
            <TableHeader>
              <TableRow>
                <TableHead>Event Time</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Category / Type</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Normalization</TableHead>
                <TableHead>Enrichment</TableHead>
                {onSelectNormalizedEvent && <TableHead className="text-right">Details</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((evt) => {
                const key = getNormalizedEventKey(evt)
                const isSelected = selectedEventKey === key
                const sevLevel = mapNumericSeverity(evt.severity)
                const categoryAndType =
                  [evt.event_category, evt.event_type].filter(Boolean).join(" / ") || "—"

                return (
                  <TableRow key={key} data-state={isSelected ? "selected" : undefined}>
                    <TableCell className="font-mono text-xs">
                      {evt.timestamp || evt.created_at || "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{evt.source || "—"}</TableCell>
                    <TableCell className="text-xs">{categoryAndType}</TableCell>
                    <TableCell className="font-mono text-xs">{evt.host || "—"}</TableCell>
                    <TableCell>
                      {sevLevel ? (
                        <SeverityBadge level={sevLevel} />
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <NormalizationStatusBadge status={evt.normalization_status} />
                    </TableCell>
                    <TableCell>
                      {(evt.enrichment_status ?? evt.enrichment?.status) ? (
                        <EnrichmentStatusBadge
                          status={evt.enrichment_status ?? evt.enrichment?.status}
                        />
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    {onSelectNormalizedEvent && (
                      <TableCell className="text-right">
                        <Button
                          type="button"
                          variant={isSelected ? "secondary" : "ghost"}
                          size="sm"
                          onClick={() => onSelectNormalizedEvent(evt)}
                          aria-pressed={isSelected}
                          aria-label={`Inspect normalized event ${key}`}
                        >
                          <Eye className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
                          {isSelected ? "Selected" : "Inspect"}
                        </Button>
                      </TableCell>
                    )}
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}

        {/* Pagination Controls */}
        <div className="flex items-center justify-between border-t pt-3">
          <span className="text-xs text-muted-foreground">
            Offset {filters.offset} · Limit {filters.limit}
          </span>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={!canPrev}
              onClick={() =>
                handleFilterChange("offset", Math.max(0, filters.offset - filters.limit))
              }
              aria-label="Previous page"
            >
              <ChevronLeft className="mr-1 h-4 w-4" aria-hidden="true" />
              Previous
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={!canNext}
              onClick={() => handleFilterChange("offset", filters.offset + filters.limit)}
              aria-label="Next page"
            >
              Next
              <ChevronRight className="ml-1 h-4 w-4" aria-hidden="true" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
