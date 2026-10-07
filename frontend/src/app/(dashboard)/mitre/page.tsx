import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"

export default function MitrePage() {
  return (
    <PageContainer 
      title="MITRE ATT&CK" 
      description="Coverage mapping and tactics, techniques, and procedures (TTPs) analysis."
    >
      <EmptyState title="No data available yet" description="No TTP data has been mapped." />
    </PageContainer>
  )
}
