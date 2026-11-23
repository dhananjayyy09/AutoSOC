import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"
import { INVESTIGATIONS_CONFIG } from "@/features/investigations"

export default function InvestigationsPage() {
  return (
    <PageContainer 
      title={INVESTIGATIONS_CONFIG.title} 
      description={INVESTIGATIONS_CONFIG.description}
    >
      <EmptyState title="No data available yet" description={INVESTIGATIONS_CONFIG.emptyMessage} />
    </PageContainer>
  )
}
