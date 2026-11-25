"use client"

import * as React from "react"
import { PageContainer } from "@/components/layout/page-container"
import {
  EVENTS_CONFIG,
  EventIngestionForm,
  NormalizedEventView,
  RecentEventsList,
} from "@/features/events"
import {
  ApiError,
  fetchNormalizedEventById,
  fetchNormalizedEvents,
  isNetworkError,
} from "@/lib/api"
import type { IngestedEventRecord, NormalizedSecurityEvent } from "@/types"

export default function EventsPage() {
  const [refreshTrigger, setRefreshTrigger] = React.useState(0)
  const [selectedEvent, setSelectedEvent] = React.useState<IngestedEventRecord | null>(null)
  const [normalizedEvent, setNormalizedEvent] = React.useState<NormalizedSecurityEvent | null>(null)
  const [isLoadingNormalized, setIsLoadingNormalized] = React.useState(false)
  const [normalizedError, setNormalizedError] = React.useState<string | null>(null)
  const requestCounterRef = React.useRef(0)

  const loadNormalizedForEvent = React.useCallback(async (evt: IngestedEventRecord | null) => {
    const requestId = ++requestCounterRef.current

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

  const handleIngestionSuccess = () => {
    setRefreshTrigger((prev) => prev + 1)
  }

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

        <NormalizedEventView
          rawEnvelope={selectedEvent}
          normalizedEvent={normalizedEvent}
          isLoading={isLoadingNormalized}
          error={normalizedError}
          onRetry={() => void loadNormalizedForEvent(selectedEvent)}
        />
      </div>
    </PageContainer>
  )
}
