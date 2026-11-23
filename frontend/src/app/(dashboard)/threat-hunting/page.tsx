import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"
import { THREAT_HUNTING_CONFIG } from "@/features/threat-hunting"

export default function ThreatHuntingPage() {
  return (
    <PageContainer 
      title={THREAT_HUNTING_CONFIG.title} 
      description={THREAT_HUNTING_CONFIG.description}
    >
      <EmptyState title="No data available yet" description={THREAT_HUNTING_CONFIG.emptyMessage} />
    </PageContainer>
  )
}
