import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"
import { INCIDENTS_CONFIG } from "@/features/incidents"

export default function IncidentsPage() {
  return (
    <PageContainer 
      title={INCIDENTS_CONFIG.title} 
      description={INCIDENTS_CONFIG.description}
    >
      <EmptyState title="No data available yet" description={INCIDENTS_CONFIG.emptyMessage} />
    </PageContainer>
  )
}
