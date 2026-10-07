import * as React from "react"
import { cn } from "@/lib/utils"

interface StatusIndicatorProps extends React.HTMLAttributes<HTMLDivElement> {
  status: "online" | "offline" | "warning" | "loading"
}

export function StatusIndicator({ status, className, ...props }: StatusIndicatorProps) {
  return (
    <div className={cn("flex items-center space-x-2", className)} {...props}>
      <span className="relative flex h-3 w-3">
        {status === "online" && (
          <>
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
          </>
        )}
        {status === "offline" && (
          <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
        )}
        {status === "warning" && (
          <>
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-yellow-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-yellow-500"></span>
          </>
        )}
        {status === "loading" && (
          <span className="relative inline-flex rounded-full h-3 w-3 bg-blue-500 animate-pulse"></span>
        )}
      </span>
      <span className="text-sm font-medium capitalize text-muted-foreground">
        {status}
      </span>
    </div>
  )
}
