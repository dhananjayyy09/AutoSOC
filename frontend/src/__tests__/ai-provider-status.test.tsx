import React from 'react'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import {
  AI_PROVIDER_STATUS_ENDPOINT,
  AiProviderStatusPanel,
  fetchAiProviderStatus,
  normalizeAiProviderStatus,
} from '@/features/system'

// ---------------------------------------------------------------------------
// Normalization & Secret Sanitization
// ---------------------------------------------------------------------------
describe('normalizeAiProviderStatus (Day 12 contract normalization & sanitization)', () => {
  it('maps ready operational metadata and strips credentials, traces, prompts, and raw outputs', () => {
    const normalized = normalizeAiProviderStatus({
      provider_name: 'ollama',
      model_name: 'llama3.1:8b',
      status: 'ready',
      enabled: true,
      configured: true,
      status_message: 'Connected api_key=topsecret sk-abc123456789\nTraceback: internal details',
      last_checked_at: '2026-11-28T17:00:00Z',
      api_key: 'SHOULD_NOT_APPEAR',
      prompt: 'raw user prompt text',
      response: 'raw llm output',
      exception: 'ValueError internal trace',
    })

    expect(normalized).toEqual({
      provider: 'ollama',
      model: 'llama3.1:8b',
      status: 'ready',
      enabled: true,
      configured: true,
      message: 'Connected api_key=[REDACTED] [REDACTED]',
      checked_at: '2026-11-28T17:00:00Z',
    })

    const serialized = JSON.stringify(normalized)
    expect(serialized).not.toContain('SHOULD_NOT_APPEAR')
    expect(serialized).not.toContain('topsecret')
    expect(serialized).not.toContain('sk-abc123456789')
    expect(serialized).not.toContain('raw user prompt text')
    expect(serialized).not.toContain('raw llm output')
    expect(serialized).not.toContain('Traceback')
  })

  it('enforces conservative precedence for disabled, unconfigured, 503, and unknown statuses', () => {
    expect(
      normalizeAiProviderStatus({
        provider: 'ollama',
        enabled: false,
        configured: true,
        status: 'ready',
      }).status
    ).toBe('disabled')

    expect(
      normalizeAiProviderStatus({
        enabled: true,
        configured: false,
        status: 'ok',
      }).status
    ).toBe('unconfigured')

    // HTTP 503 must never be promoted to 'ready'
    expect(
      normalizeAiProviderStatus({
        provider: 'ollama',
        status: 'ready',
      }, 503).status
    ).toBe('unavailable')

    expect(
      normalizeAiProviderStatus({
        provider: 'ollama',
        status: 'unrecognized_vendor_state',
      }).status
    ).toBe('error')
  })

  it('throws on malformed non-object payloads or missing recognizable fields', () => {
    expect(() => normalizeAiProviderStatus(null)).toThrow()
    expect(() => normalizeAiProviderStatus(['bad'])).toThrow()
    expect(() => normalizeAiProviderStatus({})).toThrow()
  })
})

// ---------------------------------------------------------------------------
// fetchAiProviderStatus endpoint & error separation
// ---------------------------------------------------------------------------
describe('fetchAiProviderStatus (mocked fetch)', () => {
  const originalFetch = global.fetch

  afterEach(() => {
    global.fetch = originalFetch
    jest.restoreAllMocks()
  })

  it('returns supported: false for HTTP 404 and HTTP 501 without throwing', async () => {
    global.fetch = jest
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 404, statusText: 'Not Found', json: async () => ({}) })
      .mockResolvedValueOnce({ ok: false, status: 501, statusText: 'Not Implemented', json: async () => ({}) }) as unknown as typeof fetch

    await expect(fetchAiProviderStatus()).resolves.toEqual({ supported: false })
    await expect(fetchAiProviderStatus()).resolves.toEqual({ supported: false })
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining(AI_PROVIDER_STATUS_ENDPOINT),
      expect.objectContaining({ method: 'GET', cache: 'no-store' })
    )
  })

  it('normalizes structured HTTP 503 unavailable status conservatively', async () => {
    global.fetch = jest.fn().mockResolvedValueOnce({
      ok: false,
      status: 503,
      statusText: 'Service Unavailable',
      json: async () => ({
        detail: {
          provider: 'ollama',
          model: 'llama3.1:8b',
          status: 'unavailable',
          message: 'Connection refused to local runtime',
        },
      }),
    }) as unknown as typeof fetch

    const result = await fetchAiProviderStatus()
    expect(result).toEqual({
      supported: true,
      data: {
        provider: 'ollama',
        model: 'llama3.1:8b',
        status: 'unavailable',
        enabled: null,
        configured: null,
        message: 'Connection refused to local runtime',
        checked_at: null,
      },
    })
  })

  it('throws on HTTP 500 server failures and network errors rather than reporting ready/unsupported', async () => {
    global.fetch = jest
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 500, statusText: 'Internal Server Error', json: async () => ({}) })
      .mockRejectedValueOnce(new TypeError('Failed to fetch')) as unknown as typeof fetch

    await expect(fetchAiProviderStatus()).rejects.toMatchObject({ status: 500 })
    await expect(fetchAiProviderStatus()).rejects.toThrow('Failed to fetch')
  })
})

// ---------------------------------------------------------------------------
// AiProviderStatusPanel UI States & Interactions
// ---------------------------------------------------------------------------
describe('AiProviderStatusPanel', () => {
  const originalFetch = global.fetch

  afterEach(() => {
    global.fetch = originalFetch
    jest.restoreAllMocks()
  })

  it('renders loading state while resolving and displays sanitized ready state without claiming active AI analysis', async () => {
    let resolveFetch!: (val: unknown) => void
    global.fetch = jest.fn(
      () =>
        new Promise((resolve) => {
          resolveFetch = resolve
        })
    ) as unknown as typeof fetch

    render(<AiProviderStatusPanel />)

    expect(screen.getByText('AI Provider Status')).toBeInTheDocument()
    expect(screen.getByText('Checking AI provider status...')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /refresh ai provider status/i })).toBeDisabled()

    resolveFetch({
      ok: true,
      status: 200,
      json: async () => ({
        provider: 'ollama',
        model: 'qwen2.5:7b',
        status: 'ready',
        enabled: true,
        configured: true,
        message: 'Runtime healthy',
        checked_at: '2026-11-28T17:10:00Z',
      }),
    })

    await waitFor(() => {
      expect(screen.getByText('Ready')).toBeInTheDocument()
    })

    expect(screen.getAllByText('ollama').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('qwen2.5:7b')).toBeInTheDocument()
    expect(screen.getByText('Runtime healthy')).toBeInTheDocument()
    expect(screen.getByText('2026-11-28T17:10:00Z')).toBeInTheDocument()
    expect(
      screen.getByText(/does not indicate active event analysis or autonomous agent execution/i)
    ).toBeInTheDocument()
  })

  it.each([
    ['disabled', 'Disabled', /disabled in backend configuration/i],
    ['unconfigured', 'Unconfigured', /no ai provider or model is configured/i],
    ['unavailable', 'Unavailable', /could not be reached or is currently degraded/i],
    ['error', 'Error', /reported an ai provider operational error/i],
  ] as const)(
    'renders %s status cleanly with accessible label and distinct copy',
    async (backendStatus, expectedBadge, expectedDescription) => {
      global.fetch = jest.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          provider: backendStatus === 'unconfigured' ? null : 'ollama',
          status: backendStatus,
        }),
      }) as unknown as typeof fetch

      render(<AiProviderStatusPanel />)

      await waitFor(() => {
        expect(screen.getByText(expectedBadge)).toBeInTheDocument()
      })
      expect(
        screen.getByRole('status', { name: `AI provider operational state: ${expectedBadge}` })
      ).toBeInTheDocument()
      expect(screen.getByText(expectedDescription)).toBeInTheDocument()
    }
  )

  it('distinguishes HTTP 404/501 unsupported endpoint from server/network errors', async () => {
    global.fetch = jest.fn().mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      json: async () => ({}),
    }) as unknown as typeof fetch

    render(<AiProviderStatusPanel />)

    await waitFor(() => {
      expect(
        screen.getByText('AI provider status endpoint not exposed by backend')
      ).toBeInTheDocument()
    })
    expect(screen.queryByText('Ready')).not.toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('displays safe error state on 500/network failure and recovers via manual retry/refresh without polling', async () => {
    jest.useFakeTimers()
    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: async () => ({ detail: 'Internal stack trace should never display' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          provider: 'ollama',
          model: 'llama3.1:8b',
          status: 'ready',
        }),
      })
    global.fetch = fetchMock as unknown as typeof fetch

    render(<AiProviderStatusPanel />)

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
    expect(
      screen.getByText('The server encountered an unexpected error. Please try again later.')
    ).toBeInTheDocument()
    expect(screen.queryByText(/Internal stack trace/)).not.toBeInTheDocument()

    // Ensure no background polling fires while idle
    jest.advanceTimersByTime(60_000)
    expect(fetchMock).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByRole('button', { name: /try again/i }))

    await waitFor(() => {
      expect(screen.getByText('Ready')).toBeInTheDocument()
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)
    jest.useRealTimers()
  })

  it('supports manual-only check when autoFetch is false', async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        provider: 'ollama',
        model: 'llama3.1:8b',
        status: 'ready',
      }),
    })
    global.fetch = fetchMock as unknown as typeof fetch

    render(<AiProviderStatusPanel autoFetch={false} />)

    expect(
      screen.getByText('AI provider readiness has not been checked in this session.')
    ).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Check Status' }))

    await waitFor(() => {
      expect(screen.getByText('Ready')).toBeInTheDocument()
    })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
