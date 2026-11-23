import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"
import { HealthCheck } from "@/features/system"

export default function DashboardPage() {
  return (
    <PageContainer
      title="Dashboard"
      description="High-level overview of security posture, active threats, and system health."
    >
      <div className="grid gap-6 lg:grid-cols-2">
        <HealthCheck />
        <EmptyState title="No security events yet" description="System is initializing or no events have been ingested." />
      </div>
    </PageContainer>
  )
}
