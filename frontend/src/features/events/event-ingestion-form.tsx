"use client"

import * as React from "react"
import { AlertCircle, CheckCircle2, Loader2, Send, RotateCcw } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ApiError, ingestSecurityEvent, isNetworkError } from "@/lib/api"
import type { BackendValidationErrorItem, EventIngestionRequest, EventIngestionResponse } from "@/types"

interface EventIngestionFormProps {
  onSuccess?: (response: EventIngestionResponse) => void
}

interface SubmissionError {
  title: string
  message: string
  fieldErrors?: BackendValidationErrorItem[]
}

export function EventIngestionForm({ onSuccess }: EventIngestionFormProps) {
  const [rawJson, setRawJson] = React.useState("")
  const [isSubmitting, setIsSubmitting] = React.useState(false)
  const [validationError, setValidationError] = React.useState<string | null>(null)
  const [submissionError, setSubmissionError] = React.useState<SubmissionError | null>(null)
  const [successResult, setSuccessResult] = React.useState<EventIngestionResponse | null>(null)
  const isMountedRef = React.useRef(true)

  React.useEffect(() => {
    isMountedRef.current = true
    return () => {
      isMountedRef.current = false
    }
  }, [])

  const validateJsonInput = (input: string): { valid: true; payload: EventIngestionRequest } | { valid: false; error: string } => {
    const trimmed = input.trim()
    if (!trimmed) {
      return { valid: false, error: "Event JSON payload is required." }
    }

    let parsed: unknown
    try {
      parsed = JSON.parse(trimmed)
    } catch {
      return { valid: false, error: "Invalid JSON syntax. Please verify brackets, quotes, and commas." }
    }

    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return { valid: false, error: "Payload must be a JSON object (e.g. {\"source\": \"sysmon\", ...})." }
    }

    return { valid: true, payload: parsed as EventIngestionRequest }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setRawJson(e.target.value)
    if (validationError) setValidationError(null)
    if (submissionError) setSubmissionError(null)
  }

  const handleClear = () => {
    setRawJson("")
    setValidationError(null)
    setSubmissionError(null)
    setSuccessResult(null)
  }

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (isSubmitting) return

    setValidationError(null)
    setSubmissionError(null)
    setSuccessResult(null)

    const validation = validateJsonInput(rawJson)
    if (!validation.valid) {
      setValidationError(validation.error)
      return
    }

    setIsSubmitting(true)
    try {
      const response = await ingestSecurityEvent(validation.payload)
      if (!isMountedRef.current) return
      setSuccessResult(response)
      onSuccess?.(response)
    } catch (err) {
      if (!isMountedRef.current) return

      if (err instanceof ApiError) {
        const fieldErrors = err.validationErrors
        setSubmissionError({
          title: err.status === 422 ? "Validation Error" : `Request Failed (HTTP ${err.status})`,
          message: err.userMessage,
          fieldErrors: fieldErrors.length > 0 ? fieldErrors : undefined,
        })
      } else if (isNetworkError(err)) {
        setSubmissionError({
          title: "Network Error",
          message: "Unable to reach the ingestion backend. Check your connection and try again.",
        })
      } else {
        setSubmissionError({
          title: "Ingestion Failed",
          message: "An unexpected error occurred while submitting the event.",
        })
      }
    } finally {
      if (isMountedRef.current) {
        setIsSubmitting(false)
      }
    }
  }

  const hasInputError = Boolean(validationError)
  const errorId = "event-json-error"

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">Submit Security Event</CardTitle>
        <CardDescription>
          Send a JSON security event payload to the backend ingestion API.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          <div className="space-y-2">
            <label
              htmlFor="event-json-input"
              className="block text-sm font-medium leading-none"
            >
              Event Payload (JSON)
            </label>
            <textarea
              id="event-json-input"
              name="eventJson"
              rows={10}
              value={rawJson}
              onChange={handleInputChange}
              disabled={isSubmitting}
              aria-invalid={hasInputError}
              aria-describedby={hasInputError ? errorId : "event-json-hint"}
              placeholder={'{\n  "source_type": "sysmon",\n  "sensor_id": "sensor-01",\n  "raw_payload": "..."\n}'}
              className="flex min-h-[200px] w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-sm leading-relaxed shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
            />
            <p id="event-json-hint" className="text-xs text-muted-foreground">
              Enter a valid JSON object matching the backend ingestion schema.
            </p>
          </div>

          {validationError && (
            <div
              id={errorId}
              role="alert"
              className="flex items-start gap-2.5 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{validationError}</span>
            </div>
          )}

          {submissionError && (
            <div
              role="alert"
              aria-live="assertive"
              className="space-y-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
            >
              <div className="flex items-start gap-2.5">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                <div className="space-y-1">
                  <p className="font-medium">{submissionError.title}</p>
                  <p className="text-destructive/90">{submissionError.message}</p>
                </div>
              </div>
              {submissionError.fieldErrors && (
                <ul className="ml-6 list-disc space-y-1 text-xs text-destructive/90">
                  {submissionError.fieldErrors.map((item, idx) => (
                    <li key={`${item.field ?? "field"}-${idx}`}>
                      {item.field ? <span className="font-mono font-semibold">{item.field}: </span> : null}
                      {item.message}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {successResult && (
            <div
              role="status"
              aria-live="polite"
              className="space-y-2 rounded-md border border-green-500/30 bg-green-500/10 p-3 text-sm text-green-400"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 font-medium">
                  <CheckCircle2 className="h-4 w-4 shrink-0" aria-hidden="true" />
                  <span>Event Accepted for Ingestion</span>
                </div>
                <Badge variant="outline" className="border-green-500/40 text-green-300">
                  {successResult.status}
                </Badge>
              </div>
              <dl className="grid gap-1 text-xs text-muted-foreground sm:grid-cols-2">
                <div>
                  <dt className="inline font-medium text-foreground">Ingestion ID: </dt>
                  <dd className="inline font-mono">{successResult.ingestion_id}</dd>
                </div>
                {successResult.event_id && (
                  <div>
                    <dt className="inline font-medium text-foreground">Event ID: </dt>
                    <dd className="inline font-mono">{successResult.event_id}</dd>
                  </div>
                )}
                {(successResult.ingest_time || successResult.timestamp) && (
                  <div>
                    <dt className="inline font-medium text-foreground">Ingest Time: </dt>
                    <dd className="inline font-mono">
                      {successResult.ingest_time || successResult.timestamp}
                    </dd>
                  </div>
                )}
              </dl>
              {successResult.message && (
                <p className="text-xs text-muted-foreground">{successResult.message}</p>
              )}
            </div>
          )}

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <Button
              type="submit"
              disabled={isSubmitting}
              aria-busy={isSubmitting}
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden="true" />
                  Submitting...
                </>
              ) : (
                <>
                  <Send className="mr-2 h-4 w-4" aria-hidden="true" />
                  Submit Event
                </>
              )}
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={handleClear}
              disabled={isSubmitting}
            >
              <RotateCcw className="mr-2 h-4 w-4" aria-hidden="true" />
              Clear
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  )
}
