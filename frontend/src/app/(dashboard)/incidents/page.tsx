import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"

export default function IncidentsPage() {
  return (
    <PageContainer 
      title="Incidents" 
      description="Confirmed security incidents escalated from alerts or manual creation."
    >
      <EmptyState title="No data available yet" description="No active incidents." />
    </PageContainer>
  )
}
