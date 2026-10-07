import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"

export default function AlertsPage() {
  return (
    <PageContainer 
      title="Alerts" 
      description="Real-time security alerts requiring triage and initial analysis."
    >
      <EmptyState title="No data available yet" description="No alerts have been triggered." />
    </PageContainer>
  )
}
