import * as React from "react"
import { Database } from "lucide-react"

export function EmptyState({ 
  title = "No data available", 
  description = "There is currently no data to display in this view." 
}: { 
  title?: string
  description?: string 
}) {
  return (
    <div className="flex h-[400px] w-full flex-col items-center justify-center space-y-4 rounded-lg border border-dashed p-8 text-center animate-in fade-in-50">
      <div className="rounded-full bg-muted p-4">
        <Database className="h-8 w-8 text-muted-foreground" />
      </div>
      <div className="space-y-1">
        <h3 className="font-medium tracking-tight">{title}</h3>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
    </div>
  )
}
