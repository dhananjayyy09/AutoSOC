import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"
import { THREAT_INTEL_CONFIG } from "@/features/threat-intelligence"

export default function ThreatIntelPage() {
  return (
    <PageContainer 
      title={THREAT_INTEL_CONFIG.title} 
      description={THREAT_INTEL_CONFIG.description}
    >
      <EmptyState title="No data available yet" description={THREAT_INTEL_CONFIG.emptyMessage} />
    </PageContainer>
  )
}
