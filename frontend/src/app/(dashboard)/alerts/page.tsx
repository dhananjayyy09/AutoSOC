import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"
import { ALERTS_CONFIG } from "@/features/alerts"

export default function AlertsPage() {
  return (
    <PageContainer
      title={ALERTS_CONFIG.title}
      description={ALERTS_CONFIG.description}
    >
      <EmptyState title="No data available yet" description={ALERTS_CONFIG.emptyMessage} />
    </PageContainer>
  )
}
