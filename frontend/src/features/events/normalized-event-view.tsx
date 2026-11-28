"use client"

import * as React from "react"
import { FileCode2, Layers } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { SeverityBadge } from "@/components/ui/severity-badge"
import { LoadingState } from "@/components/ui/loading-state"
import { ErrorState } from "@/components/ui/error-state"
import { EmptyState } from "@/components/ui/empty-state"
import { NormalizationStatusBadge } from "./normalization-status-badge"
import { EnrichmentContextPanel } from "./enrichment-context-panel"
import type { IngestedEventRecord, NormalizedSecurityEvent, SeverityLevel } from "@/types"

interface NormalizedEventViewProps {
  rawEnvelope?: IngestedEventRecord | null
  normalizedEvent?: NormalizedSecurityEvent | null
  isLoading?: boolean
  error?: string | null
  onRetry?: () => void
  onRetryEnrichment?: (eventId: string) => void
  isRetryingEnrichment?: boolean
  retryEnrichmentError?: string | null
}

function mapNumericSeverity(severity: number | null | undefined): SeverityLevel | null {
  if (typeof severity !== "number" || Number.isNaN(severity)) return null
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

function formatEndpoint(ip?: string | null, port?: number | null): string {
  if (!ip && (port === null || port === undefined)) return "—"
  if (ip && port !== null && port !== undefined) return `${ip}:${port}`
  return ip ?? `:${port}`
}

function FieldRow({ label, value, mono = false }: { label: string; value?: string | number | null; mono?: boolean }) {
  const displayValue = value !== null && value !== undefined && value !== "" ? String(value) : "—"
  return (
    <div className="space-y-0.5">
      <dt className="text-xs font-medium text-muted-foreground">{label}</dt>
      <dd className={mono ? "font-mono text-xs break-all text-foreground" : "text-xs text-foreground"}>
        {displayValue}
      </dd>
    </div>
  )
}

export function NormalizedEventView({
  rawEnvelope,
  normalizedEvent,
  isLoading = false,
  error = null,
  onRetry,
  onRetryEnrichment,
  isRetryingEnrichment = false,
  retryEnrichmentError = null,
}: NormalizedEventViewProps) {
  if (!rawEnvelope && !normalizedEvent && !isLoading && !error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Event Inspection & Normalization</CardTitle>
          <CardDescription>
            Compare raw ingestion evidence against normalized security event fields.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <EmptyState
            title="No event selected"
            description="Select an ingested event from Recent Ingestions to inspect its raw envelope and normalization status."
            className="h-[220px]"
          />
        </CardContent>
      </Card>
    )
  }

  const severityLevel = mapNumericSeverity(normalizedEvent?.severity)
  const effectiveStatus = normalizedEvent?.normalization_status ?? rawEnvelope?.status

  return (
    <Card>
      <CardHeader className="space-y-1">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-lg">Event Inspection & Normalization</CardTitle>
          <div className="flex flex-wrap items-center gap-3">
            {rawEnvelope && (
              <div className="flex items-center gap-1.5">
                <span className="text-xs font-medium text-muted-foreground">Ingestion:</span>
                <Badge variant="outline" aria-label={`Ingestion status: ${rawEnvelope.status}`}>
                  {rawEnvelope.status}
                </Badge>
              </div>
            )}
            <div className="flex items-center gap-1.5">
              <span className="text-xs font-medium text-muted-foreground">Normalization:</span>
              <NormalizationStatusBadge
                status={effectiveStatus}
                warnings={normalizedEvent?.warnings}
                errors={normalizedEvent?.errors}
              />
            </div>
          </div>
        </div>
        <CardDescription>
          Raw ingestion evidence is kept separate from normalized schema fields.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Raw Ingestion Evidence */}
        <section aria-label="Raw ingestion envelope" className="space-y-3 rounded-md border bg-muted/20 p-4">
          <div className="flex items-center justify-between gap-2 border-b pb-2">
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <FileCode2 className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
              Raw Ingestion Envelope
            </h3>
            {rawEnvelope?.possible_duplicate && (
              <Badge variant="outline" className="border-amber-500/40 text-amber-300">
                duplicate raw_hash
              </Badge>
            )}
          </div>

          {rawEnvelope ? (
            <div className="space-y-3">
              <dl className="grid gap-3 sm:grid-cols-2">
                <FieldRow label="Ingestion ID" value={rawEnvelope.ingestion_id} mono />
                <FieldRow label="Source Type" value={rawEnvelope.source_type ?? rawEnvelope.source} mono />
                <FieldRow label="Sensor ID" value={rawEnvelope.sensor_id} mono />
                <FieldRow
                  label="Received / Ingest Time"
                  value={rawEnvelope.received_at ?? rawEnvelope.ingest_time ?? rawEnvelope.timestamp}
                  mono
                />
                <FieldRow label="Raw Hash" value={rawEnvelope.raw_hash} mono />
                <FieldRow
                  label="Payload Size"
                  value={
                    typeof rawEnvelope.payload_size_bytes === "number"
                      ? `${rawEnvelope.payload_size_bytes} bytes`
                      : null
                  }
                />
              </dl>

              <div className="space-y-1">
                <p className="text-xs font-medium text-muted-foreground">Raw Payload Preview</p>
                <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-background p-2.5 font-mono text-xs text-foreground">
                  {rawEnvelope.raw_payload_preview ?? "No raw payload preview returned."}
                </pre>
              </div>
            </div>
          ) : (
            <EmptyState
              title="No raw envelope attached"
              description="Raw envelope metadata was not included for this record."
              className="h-[180px]"
            />
          )}
        </section>

        {/* Normalized Security Event */}
        <section aria-label="Normalized security event" className="space-y-3 rounded-md border bg-muted/20 p-4">
          <div className="flex items-center justify-between gap-2 border-b pb-2">
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <Layers className="h-4 w-4 text-primary" aria-hidden="true" />
              Normalized Event Representation
            </h3>
            {severityLevel && <SeverityBadge level={severityLevel} />}
          </div>

          {isLoading && (
            <LoadingState text="Loading normalized event data..." className="h-[220px]" />
          )}

          {!isLoading && error && (
            <ErrorState
              title="Unable to Load Normalized Event"
              description={error}
              onRetry={onRetry}
              className="h-[220px]"
            />
          )}

          {!isLoading && !error && !normalizedEvent && (
            <EmptyState
              title="Normalized event not available yet"
              description="This event is persisted as a raw envelope. No normalized record was returned for this ingestion ID."
              className="h-[220px]"
            />
          )}

          {!isLoading && !error && normalizedEvent && (
            <dl className="grid gap-3 sm:grid-cols-2">
              <FieldRow label="Event ID" value={normalizedEvent.event_id} mono />
              <FieldRow label="Event Timestamp" value={normalizedEvent.timestamp} mono />
              <FieldRow label="Source Type" value={normalizedEvent.source} mono />
              <FieldRow label="Host / Sensor" value={normalizedEvent.host ?? normalizedEvent.sensor_id} mono />
              <FieldRow label="Event Category" value={normalizedEvent.event_category} />
              <FieldRow label="Event Type" value={normalizedEvent.event_type} mono />
              <FieldRow
                label="Source Address"
                value={formatEndpoint(normalizedEvent.source_ip, normalizedEvent.source_port)}
                mono
              />
              <FieldRow
                label="Destination Address"
                value={formatEndpoint(normalizedEvent.destination_ip, normalizedEvent.destination_port)}
                mono
              />
              <FieldRow label="Protocol" value={normalizedEvent.protocol} mono />
              <FieldRow label="User" value={normalizedEvent.user} mono />
              <FieldRow label="Process" value={normalizedEvent.process} mono />
              <FieldRow label="Domain" value={normalizedEvent.domain} mono />
              <div className="sm:col-span-2">
                <FieldRow label="File Hash" value={normalizedEvent.file_hash} mono />
              </div>
              {normalizedEvent.command_line && (
                <div className="sm:col-span-2 space-y-1">
                  <dt className="text-xs font-medium text-muted-foreground">Command Line</dt>
                  <dd>
                    <pre className="max-h-24 overflow-auto whitespace-pre-wrap break-all rounded-md border bg-background p-2 font-mono text-xs text-foreground">
                      {normalizedEvent.command_line}
                    </pre>
                  </dd>
                </div>
              )}
            </dl>
          )}
        </section>
        </div>

        {!isLoading && !error && normalizedEvent && (
          <EnrichmentContextPanel
            enrichment={normalizedEvent.enrichment}
            enrichmentStatus={normalizedEvent.enrichment_status}
            onRetryEnrichment={
              onRetryEnrichment && normalizedEvent.event_id
                ? () => onRetryEnrichment(normalizedEvent.event_id!)
                : undefined
            }
            isRetryingEnrichment={isRetryingEnrichment}
            retryEnrichmentError={retryEnrichmentError}
          />
        )}
      </CardContent>
    </Card>
  )
}
