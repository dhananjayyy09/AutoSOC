"use client"

import * as React from "react"
import { PageContainer } from "@/components/layout/page-container"
import { useApiRequest } from "@/hooks/use-api-request"
import {
  EVENTS_CONFIG,
  EventIngestionForm,
  NormalizedEventExplorer,
  NormalizedEventView,
  ProviderStatusPanel,
  RecentEventsList,
  getNormalizedEventKey,
} from "@/features/events"
import {
  ApiError,
  fetchNormalizedEventById,
  fetchNormalizedEvents,
  fetchThreatIntelProvidersStatus,
  isNetworkError,
  retryNormalizedEventEnrichment,
} from "@/lib/api"
import type {
  IngestedEventRecord,
  NormalizedSecurityEvent,
  ThreatIntelProvidersStatusResult,
} from "@/types"

export default function EventsPage() {
  const [refreshTrigger, setRefreshTrigger] = React.useState(0)
  const [selectedEvent, setSelectedEvent] = React.useState<IngestedEventRecord | null>(null)
  const [normalizedEvent, setNormalizedEvent] = React.useState<NormalizedSecurityEvent | null>(null)
  const [isLoadingNormalized, setIsLoadingNormalized] = React.useState(false)
  const [normalizedError, setNormalizedError] = React.useState<string | null>(null)
  const [isRetryingEnrichment, setIsRetryingEnrichment] = React.useState(false)
  const [retryEnrichmentError, setRetryEnrichmentError] = React.useState<string | null>(null)
  const requestCounterRef = React.useRef(0)

  const {
    status: providersRequestStatus,
    data: providersData,
    error: providersError,
    execute: executeProvidersStatus,
  } = useApiRequest<ThreatIntelProvidersStatusResult>(fetchThreatIntelProvidersStatus)

  React.useEffect(() => {
    void executeProvidersStatus()
  }, [executeProvidersStatus, refreshTrigger])

  const loadNormalizedForEvent = React.useCallback(async (evt: IngestedEventRecord | null) => {
    const requestId = ++requestCounterRef.current
    setRetryEnrichmentError(null)

    if (!evt) {
      setNormalizedEvent(null)
      setNormalizedError(null)
      setIsLoadingNormalized(false)
      return
    }

    setNormalizedEvent(null)
    setNormalizedError(null)
    setIsLoadingNormalized(true)

    try {
      let resolved: NormalizedSecurityEvent | null = null

      if (evt.event_id) {
        try {
          resolved = await fetchNormalizedEventById(evt.event_id)
        } catch (err) {
          if (!(err instanceof ApiError && err.status === 404)) {
            throw err
          }
        }
      }

      if (!resolved) {
        const recentNormalized = await fetchNormalizedEvents(100)
        resolved =
          recentNormalized.find((item) => item.ingestion_id === evt.ingestion_id) ?? null
      }

      if (requestCounterRef.current !== requestId) return
      setNormalizedEvent(resolved)
    } catch (err) {
      if (requestCounterRef.current !== requestId) return
      if (err instanceof ApiError) {
        setNormalizedError(err.userMessage)
      } else if (isNetworkError(err)) {
        setNormalizedError("Unable to reach the backend normalization endpoint.")
      } else {
        setNormalizedError("Unable to load normalized event details.")
      }
    } finally {
      if (requestCounterRef.current === requestId) {
        setIsLoadingNormalized(false)
      }
    }
  }, [])

  const handleSelectEvent = React.useCallback(
    (evt: IngestedEventRecord) => {
      setSelectedEvent(evt)
      void loadNormalizedForEvent(evt)
    },
    [loadNormalizedForEvent]
  )

  const handleSelectNormalizedFromExplorer = React.useCallback(
    async (evt: NormalizedSecurityEvent) => {
      const requestId = ++requestCounterRef.current
      setSelectedEvent(null)
      setNormalizedError(null)
      setRetryEnrichmentError(null)

      if (!evt.event_id) {
        setNormalizedEvent(evt)
        setIsLoadingNormalized(false)
        return
      }

      setNormalizedEvent(evt)
      setIsLoadingNormalized(true)

      try {
        const detail = await fetchNormalizedEventById(evt.event_id)
        if (requestCounterRef.current !== requestId) return
        setNormalizedEvent(detail)
      } catch (err) {
        if (requestCounterRef.current !== requestId) return
        if (err instanceof ApiError) {
          setNormalizedError(err.userMessage)
        } else if (isNetworkError(err)) {
          setNormalizedError("Unable to reach the backend normalization endpoint.")
        } else {
          setNormalizedError("Unable to load normalized event details.")
        }
      } finally {
        if (requestCounterRef.current === requestId) {
          setIsLoadingNormalized(false)
        }
      }
    },
    []
  )

  const handleIngestionSuccess = () => {
    setRefreshTrigger((prev) => prev + 1)
  }

  const handleRetryEnrichment = React.useCallback(async (eventId: string) => {
    setIsRetryingEnrichment(true)
    setRetryEnrichmentError(null)
    try {
      const updatedEnrichment = await retryNormalizedEventEnrichment(eventId, true)
      setNormalizedEvent((prev) => {
        if (!prev || prev.event_id !== eventId) return prev
        return {
          ...prev,
          enrichment_status: updatedEnrichment.status ?? prev.enrichment_status ?? null,
          enrichment: updatedEnrichment,
        }
      })
      void executeProvidersStatus()
    } catch (err) {
      if (err instanceof ApiError) {
        setRetryEnrichmentError(err.userMessage)
      } else if (isNetworkError(err)) {
        setRetryEnrichmentError("Unable to reach the backend enrichment retry endpoint.")
      } else {
        setRetryEnrichmentError("Unable to retry enrichment for this event.")
      }
    } finally {
      setIsRetryingEnrichment(false)
    }
  }, [executeProvidersStatus])

  return (
    <PageContainer
      title={EVENTS_CONFIG.title}
      description={EVENTS_CONFIG.description}
    >
      <div className="space-y-6">
        <div className="grid gap-6 xl:grid-cols-12">
          <div className="xl:col-span-5">
            <EventIngestionForm onSuccess={handleIngestionSuccess} />
          </div>
          <div className="xl:col-span-7">
            <RecentEventsList
              refreshTrigger={refreshTrigger}
              selectedIngestionId={selectedEvent?.ingestion_id ?? null}
              onSelectEvent={handleSelectEvent}
            />
          </div>
        </div>

        <NormalizedEventExplorer
          refreshTrigger={refreshTrigger}
          selectedEventKey={normalizedEvent ? getNormalizedEventKey(normalizedEvent) : null}
          onSelectNormalizedEvent={handleSelectNormalizedFromExplorer}
        />

        <NormalizedEventView
          rawEnvelope={selectedEvent}
          normalizedEvent={normalizedEvent}
          isLoading={isLoadingNormalized}
          error={normalizedError}
          onRetry={() => {
            if (selectedEvent) {
              void loadNormalizedForEvent(selectedEvent)
            } else if (normalizedEvent) {
              void handleSelectNormalizedFromExplorer(normalizedEvent)
            }
          }}
          onRetryEnrichment={(eventId) => {
            void handleRetryEnrichment(eventId)
          }}
          isRetryingEnrichment={isRetryingEnrichment}
          retryEnrichmentError={retryEnrichmentError}
        />

        <ProviderStatusPanel
          providers={providersData?.supported ? providersData.providers : undefined}
          tiEnabled={typeof providersData?.ti_enabled === "boolean" ? providersData.ti_enabled : null}
          generatedAt={providersData?.generated_at ?? null}
          isLoading={providersRequestStatus === "loading"}
          error={providersError}
          backendSupported={
            providersData
              ? providersData.supported
              : providersError
                ? true
                : undefined
          }
          onRetry={() => {
            void executeProvidersStatus()
          }}
        />
      </div>
    </PageContainer>
  )
}
