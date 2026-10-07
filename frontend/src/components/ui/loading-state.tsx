import * as React from "react"
import { Loader2 } from "lucide-react"

export function LoadingState({ text = "Loading..." }: { text?: string }) {
  return (
    <div className="flex h-[400px] w-full flex-col items-center justify-center space-y-4 rounded-lg border border-dashed p-8 text-center animate-in fade-in-50">
      <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      <h3 className="text-sm font-medium text-muted-foreground">{text}</h3>
    </div>
  )
}
