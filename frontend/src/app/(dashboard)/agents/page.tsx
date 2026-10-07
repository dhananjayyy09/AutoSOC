import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"

export default function AgentsPage() {
  return (
    <PageContainer 
      title="AI Agents" 
      description="Manage, monitor, and configure autonomous security agents."
    >
      <EmptyState title="No data available yet" description="No agents are currently deployed." />
    </PageContainer>
  )
}
