import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"

export default function ThreatHuntingPage() {
  return (
    <PageContainer 
      title="Threat Hunting" 
      description="Proactive searching for hidden threats within the network."
    >
      <EmptyState title="No data available yet" description="No active hunting campaigns." />
    </PageContainer>
  )
}
