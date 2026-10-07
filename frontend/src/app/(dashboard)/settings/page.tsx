import { PageContainer } from "@/components/layout/page-container"
import { EmptyState } from "@/components/ui/empty-state"

export default function SettingsPage() {
  return (
    <PageContainer 
      title="Settings" 
      description="Platform configuration, integrations, and user management."
    >
      <EmptyState title="No data available yet" description="Settings are not configurable at this time." />
    </PageContainer>
  )
}
