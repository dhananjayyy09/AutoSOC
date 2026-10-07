import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"

export default function InvestigationsPage() {
  return (
    <PageContainer 
      title="Investigations" 
      description="Deep-dive analysis of security events, evidence collection, and multi-agent correlation."
    >
      <EmptyState title="No data available yet" description="No active investigations." />
    </PageContainer>
  )
}
