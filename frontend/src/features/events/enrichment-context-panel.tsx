"use client"

import * as React from "react"
import { AlertTriangle, RotateCcw, Shield, Sparkles } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { EmptyState } from "@/components/ui/empty-state"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { sanitizeFailureCategory } from "@/lib/api"
import { EnrichmentStatusBadge } from "./enrichment-status-badge"
import { ThreatLookupStatusBadge, ThreatVerdictBadge } from "./threat-intel-status-badge"
import type { EventEnrichmentContext } from "@/types"

interface EnrichmentContextPanelProps {
  enrichment?: EventEnrichmentContext | null
  enrichmentStatus?: string | null
  onRetryEnrichment?: () => void
  isRetryingEnrichment?: boolean
  retryEnrichmentError?: string | null
}

const RETRYABLE_LOOKUP_STATUSES = new Set([
  "timeout",
  "unavailable",
  "provider_unavailable",
  "rate_limited",
  "rate_limit",
  "retry_exhausted",
  "circuit_open",
  "circuit_breaker_open",
  "failed",
  "lookup_failed",
  "error",
  "invalid_response",
  "malformed_response",
])

function isFixtureProviderName(provider: string | null | undefined): boolean {
  if (!provider) return false
  const lower = provider.toLowerCase()
  return lower.includes("fixture") || lower.includes("mock")
}

function formatConfidence(confidence: number | null | undefined): string | null {
  if (typeof confidence !== "number" || Number.isNaN(confidence)) return null
  if (confidence >= 0 && confidence <= 1) {
    return `${Math.round(confidence * 100)}%`
  }
  return `${Math.round(confidence)}%`
}

export function EnrichmentContextPanel({
  enrichment,
  enrichmentStatus,
  onRetryEnrichment,
  isRetryingEnrichment = false,
  retryEnrichmentError = null,
}: EnrichmentContextPanelProps) {
  const effectiveStatus = enrichment?.status ?? enrichmentStatus ?? null
  const observables = enrichment?.observables ?? []
  const warnings = enrichment?.warnings ?? []
  const errors = enrichment?.errors ?? []
  const hasAnyEnrichment = Boolean(enrichment || effectiveStatus)
  const threatIntel = enrichment?.context?.threat_intel ?? null
  const hasNonOfflineTI = Boolean(
    threatIntel ||
      isFixtureProviderName(enrichment?.provider) ||
      observables.some(
        (o) =>
          isFixtureProviderName(o.provider) ||
          (o.lookup_status &&
            !["offline_only", "not_queried"].includes(o.lookup_status.toLowerCase()))
      )
  )
  const headerOriginLabel = enrichment?.live_lookup_performed
    ? "Live TI Lookup"
    : hasNonOfflineTI
      ? "Fixture / Mock TI"
      : "Offline Deterministic"
  const normalizedEffectiveStatus = effectiveStatus?.trim().toLowerCase() ?? ""
  const hasRetryableOutcome = Boolean(
    hasAnyEnrichment &&
      (normalizedEffectiveStatus === "failed" ||
        normalizedEffectiveStatus === "enriched_partial" ||
        normalizedEffectiveStatus === "partial" ||
        errors.length > 0 ||
        observables.some(
          (obs) =>
            obs.retry_exhausted === true ||
            (obs.lookup_status && RETRYABLE_LOOKUP_STATUSES.has(obs.lookup_status.trim().toLowerCase()))
        ))
  )

  return (
    <section
      aria-label="Security enrichment context"
      className="space-y-3 rounded-md border bg-muted/20 p-4"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-2">
        <div className="space-y-0.5">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Sparkles className="h-4 w-4 text-primary" aria-hidden="true" />
            Enrichment-Derived Context
          </h3>
          <p className="text-xs text-muted-foreground">
            Derived observable context and threat-intelligence lookup results are kept separate from original normalized fields.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {enrichment?.enriched_at && (
            <span className="font-mono text-xs text-muted-foreground">
              Enriched: {enrichment.enriched_at}
            </span>
          )}
          <EnrichmentStatusBadge status={effectiveStatus} />
          {onRetryEnrichment && hasRetryableOutcome && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onRetryEnrichment}
              disabled={isRetryingEnrichment}
              className="h-7 gap-1.5 text-xs"
            >
              <RotateCcw
                className={isRetryingEnrichment ? "h-3.5 w-3.5 animate-spin" : "h-3.5 w-3.5"}
                aria-hidden="true"
              />
              {isRetryingEnrichment ? "Retrying Enrichment..." : "Retry Enrichment"}
            </Button>
          )}
        </div>
      </div>

      {retryEnrichmentError && (
        <div
          role="alert"
          aria-label="Enrichment retry error"
          className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive"
        >
          Manual enrichment retry failed: {retryEnrichmentError}
        </div>
      )}

      {!hasAnyEnrichment && (
        <EmptyState
          title="No enrichment available"
          description="No enrichment context has been attached to this normalized event."
          className="h-[160px]"
        />
      )}

      {hasAnyEnrichment && warnings.length > 0 && (
        <div
          role="status"
          aria-label="Enrichment warnings"
          className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-300"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <div className="space-y-1">
            <p className="font-medium">Partial enrichment warnings</p>
            <ul className="ml-4 list-disc space-y-0.5">
              {warnings.map((w, idx) => (
                <li key={`enrich-warn-${idx}`}>{w}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {hasAnyEnrichment && errors.length > 0 && (
        <div
          role="alert"
          aria-label="Enrichment errors"
          className="space-y-1 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive"
        >
          <p className="font-medium">Enrichment errors reported</p>
          <ul className="ml-4 list-disc space-y-0.5">
            {errors.map((errMsg, idx) => (
              <li key={`enrich-err-${idx}`}>{errMsg}</li>
            ))}
          </ul>
        </div>
      )}

      {hasAnyEnrichment && (
        <div
          aria-label="Deterministic local context"
          className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground"
        >
          {enrichment?.provider && (
            <Badge variant="outline" className="font-mono text-[11px]">
              Provider: {enrichment.provider}
              {enrichment.provider_version ? ` v${enrichment.provider_version}` : ""}
            </Badge>
          )}
          {typeof enrichment?.live_lookup_performed === "boolean" && (
            <Badge variant="outline" className="text-[11px]">
              {headerOriginLabel}
            </Badge>
          )}
          {typeof enrichment?.attempt_count === "number" && (
            <span className="font-mono">Attempts: {enrichment.attempt_count}</span>
          )}
          {enrichment?.context?.network && (
            <>
              {enrichment.context.network.is_external_to_internal === true && (
                <Badge variant="outline" className="text-[11px]">
                  External -&gt; Internal
                </Badge>
              )}
              {enrichment.context.network.is_internal_src !== null &&
                enrichment.context.network.is_internal_src !== undefined && (
                  <span className="font-mono">
                    Src: {enrichment.context.network.is_internal_src ? "Internal" : "External"}
                  </span>
                )}
              {enrichment.context.network.is_internal_dst !== null &&
                enrichment.context.network.is_internal_dst !== undefined && (
                  <span className="font-mono">
                    Dst: {enrichment.context.network.is_internal_dst ? "Internal" : "External"}
                  </span>
                )}
              {enrichment.context.network.dst_port_well_known !== null &&
                enrichment.context.network.dst_port_well_known !== undefined && (
                  <span className="font-mono">
                    Dst Port: {enrichment.context.network.dst_port_well_known ? "Well-Known" : "Registered/Ephemeral"}
                  </span>
                )}
            </>
          )}
          {enrichment?.context?.indicators?.domain_tld && (
            <span className="font-mono">
              TLD: .{enrichment.context.indicators.domain_tld}
            </span>
          )}
          {enrichment?.context?.indicators?.file_hash_algorithm && (
            <span className="font-mono">
              Hash: {enrichment.context.indicators.file_hash_algorithm.toUpperCase()}
            </span>
          )}
        </div>
      )}

      {hasAnyEnrichment && threatIntel && (
        <div
          aria-label="Provider-backed threat intelligence summary"
          className="space-y-2 rounded-md border border-primary/20 bg-background/60 p-3 text-xs"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="flex items-center gap-1.5 font-semibold text-foreground">
              <Shield className="h-3.5 w-3.5 text-primary" aria-hidden="true" />
              Provider Threat Intelligence Summary
            </span>
            <div className="flex flex-wrap items-center gap-2">
              {threatIntel.cached === true && (
                <Badge variant="outline" className="text-[11px] border-blue-500/40 text-blue-300">
                  Cached Result
                </Badge>
              )}
              {threatIntel.status && (
                <ThreatLookupStatusBadge status={threatIntel.status} />
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-muted-foreground">
            {threatIntel.provider && (
              <span>
                Provider: <strong className="font-mono text-foreground">{threatIntel.provider}</strong>
              </span>
            )}
            {threatIntel.sources && threatIntel.sources.length > 0 && (
              <span>
                Sources: <strong className="font-mono text-foreground">{threatIntel.sources.join(", ")}</strong>
              </span>
            )}
            {threatIntel.providers_queried && threatIntel.providers_queried.length > 0 && (
              <span>
                Providers Queried:{" "}
                <strong className="font-mono text-foreground">
                  {threatIntel.providers_queried.join(", ")}
                </strong>
              </span>
            )}
            {typeof threatIntel.live_lookups === "number" && (
              <span>
                Live Lookups:{" "}
                <strong className="font-mono text-foreground">{threatIntel.live_lookups}</strong>
              </span>
            )}
            {typeof threatIntel.cache_hits === "number" && (
              <span>
                Cache Hits:{" "}
                <strong className="font-mono text-foreground">{threatIntel.cache_hits}</strong>
              </span>
            )}
            {typeof threatIntel.ip_score === "number" && (
              <span>
                IP Score: <strong className="font-mono text-foreground">{threatIntel.ip_score}</strong>
              </span>
            )}
            {typeof threatIntel.domain_score === "number" && (
              <span>
                Domain Score: <strong className="font-mono text-foreground">{threatIntel.domain_score}</strong>
              </span>
            )}
            {typeof threatIntel.hash_known_malware === "boolean" && (
              <span>
                Known Malware Hash:{" "}
                <strong className="font-mono text-foreground">
                  {threatIntel.hash_known_malware ? "Yes" : "No"}
                </strong>
              </span>
            )}
            {formatConfidence(threatIntel.confidence) && (
              <span>
                Confidence:{" "}
                <strong className="font-mono text-foreground">
                  {formatConfidence(threatIntel.confidence)}
                </strong>
              </span>
            )}
            {threatIntel.lookup_timestamp && (
              <span className="font-mono">Looked up: {threatIntel.lookup_timestamp}</span>
            )}
          </div>

          {threatIntel.ip_categories && threatIntel.ip_categories.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-muted-foreground">Categories:</span>
              {threatIntel.ip_categories.map((cat) => (
                <Badge key={cat} variant="outline" className="text-[11px]">
                  {cat}
                </Badge>
              ))}
            </div>
          )}

          {threatIntel.evidence_summary && (
            <p className="text-muted-foreground">{threatIntel.evidence_summary}</p>
          )}
        </div>
      )}

      {hasAnyEnrichment && observables.length === 0 && errors.length === 0 && (
        <EmptyState
          title="No observables extracted"
          description="No enrichable observables were returned for this event."
          className="h-[150px]"
        />
      )}

      {observables.length > 0 && (
        <Table aria-label="Enriched observables">
          <TableHeader>
            <TableRow>
              <TableHead>Observable</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Classification / Verdict</TableHead>
              <TableHead>Lookup State</TableHead>
              <TableHead>Source / Provider</TableHead>
              <TableHead>Evidence &amp; Confidence</TableHead>
              <TableHead>Provenance</TableHead>
              <TableHead>Timestamp</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {observables.map((obs, idx) => {
              const provObj =
                obs.provenance && typeof obs.provenance === "object"
                  ? obs.provenance
                  : null
              const provenanceSummary =
                obs.source_field ||
                (provObj?.source_fields && provObj.source_fields.length > 0
                  ? provObj.source_fields.join(", ")
                  : null)
              const evidenceText = obs.evidence_summary ?? provObj?.evidence ?? null
              const confidenceText = formatConfidence(obs.confidence)
              const provenanceTitle = [
                provenanceSummary ? `Extracted from normalized field: ${provenanceSummary}` : null,
                provObj?.method ? `Method: ${provObj.method}` : null,
                evidenceText ? `Evidence: ${evidenceText}` : null,
              ]
                .filter(Boolean)
                .join(" | ")
              const obsLiveLookup =
                typeof obs.live_lookup_performed === "boolean"
                  ? obs.live_lookup_performed
                  : provObj?.live_lookup_performed
              const obsOriginLabel = obsLiveLookup
                ? "Live TI"
                : isFixtureProviderName(obs.provider) ||
                    (obs.lookup_status &&
                      !["offline_only", "not_queried"].includes(obs.lookup_status.toLowerCase()))
                  ? "Fixture TI"
                  : "Offline Deterministic"
              const timestampText = obs.lookup_timestamp ?? obs.enriched_at ?? null
              const safeFailureCategory = sanitizeFailureCategory(obs.failure_category)

              return (
                <TableRow key={`${obs.observable}-${obs.observable_type}-${idx}`}>
                  <TableCell className="font-mono text-xs break-all">
                    <div>{obs.observable}</div>
                    {obs.original_value && obs.original_value !== obs.observable && (
                      <div className="text-[11px] text-muted-foreground">
                        orig: {obs.original_value}
                      </div>
                    )}
                    {obs.cached === true && (
                      <Badge
                        variant="outline"
                        className="mt-1 text-[10px] border-blue-500/40 text-blue-300"
                      >
                        Cached Result
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{obs.observable_type || "—"}</TableCell>
                  <TableCell className="text-xs">
                    <div className="flex flex-wrap items-center gap-1">
                      {obs.classification ? (
                        <Badge variant="outline">{obs.classification}</Badge>
                      ) : !obs.verdict ? (
                        <span className="text-muted-foreground">No verdict</span>
                      ) : null}
                      {obs.verdict && <ThreatVerdictBadge verdict={obs.verdict} />}
                      {typeof obsLiveLookup === "boolean" && (
                        <span className="text-[11px] text-muted-foreground">
                          ({obsOriginLabel})
                        </span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs">
                    <div className="space-y-1">
                      {obs.lookup_status ? (
                        <ThreatLookupStatusBadge status={obs.lookup_status} />
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                      {obs.retry_exhausted && (
                        <div className="text-[11px] font-medium text-red-300">
                          Retries exhausted
                          {typeof obs.retry_count === "number" ? ` (${obs.retry_count})` : ""}
                        </div>
                      )}
                      {!obs.retry_exhausted && typeof obs.retry_count === "number" && obs.retry_count > 0 && (
                        <div className="font-mono text-[11px] text-muted-foreground">
                          Retries: {obs.retry_count}
                        </div>
                      )}
                      {safeFailureCategory && (
                        <div className="font-mono text-[11px] text-amber-300">
                          {safeFailureCategory}
                        </div>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs">{obs.provider || "—"}</TableCell>
                  <TableCell className="max-w-xs text-xs">
                    {evidenceText ? (
                      <p className="text-foreground">{evidenceText}</p>
                    ) : (
                      <span className="text-muted-foreground">No evidence summary</span>
                    )}
                    {confidenceText && (
                      <p className="font-mono text-[11px] text-muted-foreground">
                        Confidence: {confidenceText}
                      </p>
                    )}
                    {obs.references && obs.references.length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-1.5 text-[11px] text-muted-foreground">
                        {obs.references.map((ref, refIdx) => (
                          <span key={`ref-${idx}-${refIdx}`} className="font-mono">
                            [{ref.source_name}
                            {ref.reference_id ? `:${ref.reference_id}` : ""}]
                          </span>
                        ))}
                      </div>
                    )}
                  </TableCell>
                  <TableCell
                    className="font-mono text-xs"
                    title={provenanceTitle || undefined}
                  >
                    <div>{provenanceSummary || "—"}</div>
                    {provObj?.method && (
                      <div className="text-[11px] text-muted-foreground">{provObj.method}</div>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{timestampText || "—"}</TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      )}
    </section>
  )
}
