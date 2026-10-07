import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"

export default function AuditPage() {
  return (
    <PageContainer 
      title="Audit Logs" 
      description="System activity, user actions, and agent decisions."
    >
      <EmptyState title="No data available yet" description="No audit logs available." />
    </PageContainer>
  )
}
