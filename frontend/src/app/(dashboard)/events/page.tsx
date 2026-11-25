"use client"

import * as React from "react"
import { PageContainer } from "@/components/layout/page-container"
import {
  EVENTS_CONFIG,
  EventIngestionForm,
  NormalizedEventView,
  RecentEventsList,
} from "@/features/events"
import type { IngestedEventRecord } from "@/types"

export default function EventsPage() {
  const [refreshTrigger, setRefreshTrigger] = React.useState(0)
  const [selectedEvent, setSelectedEvent] = React.useState<IngestedEventRecord | null>(null)

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
              onSelectEvent={setSelectedEvent}
            />
          </div>
        </div>

        <NormalizedEventView rawEnvelope={selectedEvent} />
      </div>
    </PageContainer>
  )
}
