import * as React from "react"
import { checkHealth } from "@/lib/api"

export function useHealthCheck(intervalMs?: number) {
  const [status, setStatus] = React.useState<"loading" | "connected" | "unavailable">("loading")
  const [isRetrying, setIsRetrying] = React.useState(false)

  const performCheck = React.useCallback(async () => {
    const res = await checkHealth()
    setStatus(res.status === "connected" ? "connected" : "unavailable")
  }, [])

  const retry = React.useCallback(async () => {
    setIsRetrying(true)
    setStatus("loading")
    try {
      await performCheck()
    } finally {
      setIsRetrying(false)
    }
  }, [performCheck])

  React.useEffect(() => {
    let isMounted = true

    checkHealth()
      .then((res) => {
        if (isMounted) {
          setStatus(res.status === "connected" ? "connected" : "unavailable")
        }
      })
      .catch(() => {
        if (isMounted) {
          setStatus("unavailable")
        }
      })

    return () => {
      isMounted = false
    }
  }, [])

  React.useEffect(() => {
    if (intervalMs && status === "connected") {
      const interval = setInterval(performCheck, intervalMs)
      return () => clearInterval(interval)
    }
  }, [intervalMs, status, performCheck])

  return { status, isRetrying, retry }
}
