import * as React from "react"
import { checkReadiness } from "@/lib/api"
import type { ReadinessState, ReadinessResponse } from "@/types"

export function useReadiness(intervalMs?: number) {
  const [state, setState] = React.useState<"loading" | ReadinessState>("loading")
  const [data, setData] = React.useState<ReadinessResponse | undefined>(undefined)
  const [isRetrying, setIsRetrying] = React.useState(false)

  const performCheck = React.useCallback(async () => {
    try {
      const res = await checkReadiness()
      setState(res.state)
      setData(res.data)
    } catch {
      setState("unavailable")
    }
  }, [])

  const retry = React.useCallback(async () => {
    setIsRetrying(true)
    setState("loading")
    try {
      await performCheck()
    } finally {
      setIsRetrying(false)
    }
  }, [performCheck])

  React.useEffect(() => {
    let isMounted = true

    checkReadiness()
      .then((res) => {
        if (isMounted) {
          setState(res.state)
          setData(res.data)
        }
      })
      .catch(() => {
        if (isMounted) {
          setState("unavailable")
        }
      })

    return () => {
      isMounted = false
    }
  }, [])

  React.useEffect(() => {
    if (intervalMs && (state === "ready" || state === "degraded")) {
      const interval = setInterval(performCheck, intervalMs)
      return () => clearInterval(interval)
    }
  }, [intervalMs, state, performCheck])

  return { state, data, isRetrying, retry }
}
