import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"

export default function ThreatIntelPage() {
  return (
    <PageContainer 
      title="Threat Intelligence" 
      description="Indicators of Compromise (IoCs), actor profiles, and global threat data."
    >
      <EmptyState title="No data available yet" description="No intelligence feeds configured." />
    </PageContainer>
  )
}
