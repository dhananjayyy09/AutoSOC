import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"

export default function DashboardPage() {
  return (
    <PageContainer 
      title="Dashboard" 
      description="High-level overview of security posture, active threats, and system health."
    >
      <EmptyState title="No data available yet" description="System is initializing or no events have been ingested." />
    </PageContainer>
  )
}
