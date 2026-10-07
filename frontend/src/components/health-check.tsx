"use client"

import * as React from "react"
import { checkHealth } from "@/lib/api"
import { StatusIndicator } from "@/components/ui/status-indicator"
import { Card, CardContent } from "@/components/ui/card"
import { ShieldAlert, ShieldCheck } from "lucide-react"

export function HealthCheck() {
  const [status, setStatus] = React.useState<"loading" | "connected" | "unavailable">("loading")

  React.useEffect(() => {
    const fetchHealth = async () => {
      const res = await checkHealth()
      if (res.status === "connected") {
        setStatus("connected")
      } else {
        setStatus("unavailable")
      }
    }
    fetchHealth()
  }, [])

  if (status === "loading") {
    return (
      <Card className="w-full max-w-sm">
        <CardContent className="flex items-center justify-between p-4">
          <div className="flex items-center space-x-4">
            <div className="rounded-full bg-muted p-2">
              <ShieldAlert className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="space-y-1">
              <p className="text-sm font-medium leading-none">Backend Status</p>
              <p className="text-xs text-muted-foreground">Checking connection...</p>
            </div>
          </div>
          <StatusIndicator status="loading" />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="w-full max-w-sm">
      <CardContent className="flex items-center justify-between p-4">
        <div className="flex items-center space-x-4">
          <div className={`rounded-full p-2 ${status === "connected" ? "bg-green-500/10" : "bg-red-500/10"}`}>
            {status === "connected" ? (
              <ShieldCheck className="h-4 w-4 text-green-500" />
            ) : (
              <ShieldAlert className="h-4 w-4 text-red-500" />
            )}
          </div>
          <div className="space-y-1">
            <p className="text-sm font-medium leading-none">Backend Status</p>
            <p className="text-xs text-muted-foreground">
              {status === "connected" ? "Backend Connected" : "Backend Unavailable"}
            </p>
          </div>
        </div>
        <StatusIndicator status={status === "connected" ? "online" : "offline"} />
      </CardContent>
    </Card>
  )
}
