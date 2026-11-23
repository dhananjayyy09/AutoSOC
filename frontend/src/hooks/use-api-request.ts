import * as React from "react"
import type { AsyncState, RequestStatus } from "@/types"
import { ApiError, isNetworkError } from "@/lib/api"

// ---------------------------------------------------------------------------
// useApiRequest – generic data-fetching hook for feature components.
//
// Usage:
//   const { status, data, error, execute } = useApiRequest(fetchAlerts)
//
// Features:
//   - Provides consistent loading / success / error lifecycle
//   - Prevents state updates after unmount
//   - Sanitizes error messages so raw API errors are never shown to users
//   - Does NOT auto-fetch on mount — call execute() explicitly
// ---------------------------------------------------------------------------

export function useApiRequest<T>(
  fetcher: () => Promise<T>
): AsyncState<T> & { execute: () => Promise<void> } {
  const [status, setStatus] = React.useState<RequestStatus>("idle")
  const [data, setData] = React.useState<T | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const isMountedRef = React.useRef(true)

  React.useEffect(() => {
    isMountedRef.current = true
    return () => {
      isMountedRef.current = false
    }
  }, [])

  const execute = React.useCallback(async () => {
    if (!isMountedRef.current) return

    setStatus("loading")
    setError(null)

    try {
      const result = await fetcher()
      if (!isMountedRef.current) return
      setData(result)
      setStatus("success")
    } catch (err) {
      if (!isMountedRef.current) return
      setStatus("error")
      setData(null)

      // Sanitize: never expose raw server error strings to the UI
      if (err instanceof ApiError) {
        setError(err.userMessage)
      } else if (isNetworkError(err)) {
        setError("Unable to reach the server. Check your network connection.")
      } else if (err instanceof Error) {
        // Generic JS error – show a safe fallback
        setError("An unexpected error occurred. Please try again.")
      } else {
        setError("An unexpected error occurred.")
      }
    }
  }, [fetcher])

  return { status, data, error, execute }
}
