import React from 'react'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import {
  EnrichmentContextPanel,
  NormalizedEventView,
  ProviderStatusPanel,
  ThreatLookupStatusBadge,
  ThreatVerdictBadge,
  normalizeProviderStatusList,
  sanitizeFailureCategory,
} from '@/features/events'
import * as apiModule from '@/lib/api'
import type { EventEnrichmentContext, NormalizedSecurityEvent, ThreatIntelProviderStatus } from '@/types'

// ---------------------------------------------------------------------------
// Operational telemetry sanitization & mapping
// ---------------------------------------------------------------------------
describe('Provider operational telemetry mapping & sanitization', () => {
  it('sanitizes failure categories and strips tokens, API keys, and stack traces', () => {
    expect(sanitizeFailureCategory('rate_limit_exceeded')).toBe('rate_limit_exceeded')
    expect(
      sanitizeFailureCategory('upstream_auth_error Authorization: Bearer sk-secret-token-123')
    ).toBe('upstream_auth_error Authorization=[REDACTED]')
    expect(
      sanitizeFailureCategory('request failed api_key=supersecret\nTraceback (most recent call last):')
    ).toBe('request failed api_key=[REDACTED]')
    expect(sanitizeFailureCategory('   ')).toBeNull()
  })

  it('normalizes provider status entries while ignoring credentials/raw secrets and handling missing fields', () => {
    const mapped = normalizeProviderStatusList({
      providers: [
        {
          provider_id: 'virustotal',
          provider_name: 'VirusTotal v3',
          enabled: true,
          status: 'healthy',
          circuit_breaker_state: 'closed',
          last_success_at: '2026-11-28T10:15:00Z',
          is_live: true,
          api_key: 'SECRET_SHOULD_NOT_APPEAR',
          auth_header: 'Bearer DO_NOT_EXPOSE',
          raw_payload: { secret: true },
        },
        {
          provider_id: 'abuseipdb',
          enabled: false,
          status: 'healthy', // disabled provider must present as disabled
          failure_category: 'token=xyz987\nstack trace line',
        },
      ],
    })

    expect(mapped).toHaveLength(2)
    expect(mapped[0]).toEqual({
      provider_id: 'virustotal',
      provider_name: 'VirusTotal v3',
      enabled: true,
      status: 'healthy',
      circuit_breaker_state: 'closed',
      last_success_at: '2026-11-28T10:15:00Z',
      failure_category: null,
      is_live: true,
      retry_count: null,
      retry_exhausted: null,
    })
    expect(JSON.stringify(mapped[0])).not.toContain('SECRET_SHOULD_NOT_APPEAR')
    expect(JSON.stringify(mapped[0])).not.toContain('DO_NOT_EXPOSE')

    expect(mapped[1]).toMatchObject({
      provider_id: 'abuseipdb',
      provider_name: null,
      enabled: false,
      status: 'disabled',
      circuit_breaker_state: null,
      last_success_at: null,
      failure_category: 'token=[REDACTED]',
    })
  })
})

// ---------------------------------------------------------------------------
// ProviderStatusPanel
// ---------------------------------------------------------------------------
describe('ProviderStatusPanel (mocked operational telemetry)', () => {
  it('honestly informs analyst when global provider-status backend endpoint is not exposed', () => {
    render(<ProviderStatusPanel backendSupported={false} />)
    expect(screen.getByText('Threat Intelligence Provider Status')).toBeInTheDocument()
    expect(
      screen.getByText(/Global provider-status endpoint not exposed by backend/i)
    ).toBeInTheDocument()
    expect(screen.queryByText('Healthy')).not.toBeInTheDocument()
  })

  it('renders loading, error, and empty states cleanly', () => {
    const onRetry = jest.fn()
    const { rerender } = render(<ProviderStatusPanel isLoading />)
    expect(screen.getByText('Checking TI provider operational status...')).toBeInTheDocument()

    rerender(<ProviderStatusPanel error="Provider status API unreachable" onRetry={onRetry} />)
    expect(screen.getByText('Provider status API unreachable')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /try again/i }))
    expect(onRetry).toHaveBeenCalledTimes(1)

    rerender(<ProviderStatusPanel providers={[]} />)
    expect(screen.getByText('No TI providers reported')).toBeInTheDocument()
  })

  it('renders healthy, degraded, unavailable, disabled, circuit-breaker, and sanitized failures', () => {
    const providers: ThreatIntelProviderStatus[] = [
      {
        provider_id: 'virustotal',
        provider_name: 'VirusTotal',
        enabled: true,
        status: 'healthy',
        circuit_breaker_state: 'closed',
        last_success_at: '2026-11-28T11:00:00Z',
        is_live: true,
      },
      {
        provider_id: 'abuseipdb',
        provider_name: 'AbuseIPDB',
        enabled: true,
        status: 'degraded',
        circuit_breaker_state: 'half_open',
        failure_category: 'rate_limited Bearer secret123',
        retry_count: 2,
        is_live: true,
      },
      {
        provider_id: 'otx',
        provider_name: 'AlienVault OTX',
        enabled: true,
        status: 'unavailable',
        circuit_breaker_state: 'open',
        failure_category: 'upstream_timeout',
        retry_count: 3,
        retry_exhausted: true,
        is_live: true,
      },
      {
        provider_id: 'autosoc.mock_ti_fixture',
        provider_name: 'Mock TI Fixture',
        enabled: false,
        status: 'disabled',
        is_live: false,
      },
    ]

    render(<ProviderStatusPanel providers={providers} />)

    expect(screen.getByText('4 configured')).toBeInTheDocument()
    expect(screen.getByText('Healthy')).toBeInTheDocument()
    expect(screen.getByText('Degraded')).toBeInTheDocument()
    expect(screen.getByText('Unavailable')).toBeInTheDocument()
    expect(screen.getAllByText('Disabled').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('Circuit Closed')).toBeInTheDocument()
    expect(screen.getByText('Circuit Half-Open')).toBeInTheDocument()
    expect(screen.getByText('Circuit Open')).toBeInTheDocument()
    expect(screen.getByText('Retry Exhausted')).toBeInTheDocument()
    expect(screen.getByText('rate_limited Bearer [REDACTED]')).toBeInTheDocument()
    expect(screen.queryByText(/secret123/)).not.toBeInTheDocument()
    expect(screen.getByText('upstream_timeout')).toBeInTheDocument()
    expect(screen.getByText('2026-11-28T11:00:00Z')).toBeInTheDocument()
    expect(screen.getByText('Fixture / Deterministic')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Day 11 Lookup Outcome Badges & Verdict Separation
// ---------------------------------------------------------------------------
describe('Day 11 lookup outcome clarity', () => {
  it.each([
    ['success', 'Lookup Completed'],
    ['no_result', 'No Result'],
    ['timeout', 'Timed Out'],
    ['provider_unavailable', 'Provider Unavailable'],
    ['rate_limited', 'Rate Limited'],
    ['retry_exhausted', 'Retry Exhausted'],
    ['circuit_open', 'Circuit Breaker Open'],
    ['circuit_breaker_open', 'Circuit Breaker Open'],
    ['provider_disabled', 'Provider Disabled'],
    ['invalid_observable', 'Invalid Observable'],
    ['unsupported_observable', 'Unsupported'],
    ['malformed_response', 'Malformed Response'],
    ['invalid_response', 'Malformed Response'],
    ['skipped_limit', 'Skipped (Limit)'],
    ['offline_only', 'Offline Only'],
  ])('renders %s with distinct analyst label %s', (status, expectedLabel) => {
    render(<ThreatLookupStatusBadge status={status} />)
    expect(screen.getByText(expectedLabel)).toBeInTheDocument()
  })

  it('never renders failure outcomes or unknown verdicts with clean/benign green styling', () => {
    const failureStatuses = ['timeout', 'rate_limited', 'retry_exhausted', 'circuit_open', 'malformed_response']
    for (const status of failureStatuses) {
      const { unmount } = render(<ThreatLookupStatusBadge status={status} />)
      const badge = screen.getByLabelText(/Lookup status:/i)
      expect(badge).not.toHaveClass('text-emerald-300')
      unmount()
    }

    const { rerender } = render(<ThreatVerdictBadge verdict="unknown" />)
    expect(screen.getByLabelText('Reputation verdict: unknown')).toHaveClass('text-slate-300')

    rerender(<ThreatVerdictBadge verdict="benign" />)
    expect(screen.getByLabelText('Reputation verdict: benign')).toHaveClass('text-emerald-300')

    rerender(<ThreatVerdictBadge verdict="malicious" />)
    expect(screen.getByLabelText('Reputation verdict: malicious')).toHaveClass('text-red-300')
  })
})

// ---------------------------------------------------------------------------
// Retry & Recovery Feedback in EnrichmentContextPanel & NormalizedEventView
// ---------------------------------------------------------------------------
describe('Manual enrichment retry & recovery feedback (mocked API)', () => {
  const originalFetch = global.fetch

  afterEach(() => {
    global.fetch = originalFetch
    jest.restoreAllMocks()
  })

  it('displays rate_limited, retry_exhausted, circuit_open, malformed_response, failure categories, and manual retry control', () => {
    const onRetryEnrichment = jest.fn()
    const enrichment: EventEnrichmentContext = {
      status: 'enriched_partial',
      provider: 'autosoc.ti_coordinator',
      live_lookup_performed: true,
      attempt_count: 2,
      context: {
        threat_intel: {
          status: 'provider_unavailable',
          providers_queried: ['virustotal', 'abuseipdb'],
          live_lookups: 2,
          cache_hits: 1,
        },
      },
      observables: [
        {
          observable: '198.51.100.12',
          observable_type: 'ip',
          verdict: 'unknown',
          lookup_status: 'rate_limited',
          provider: 'virustotal',
          retry_count: 1,
          failure_category: 'http_429_rate_limit',
          live_lookup_performed: true,
        },
        {
          observable: 'bad.example.org',
          observable_type: 'domain',
          verdict: 'unknown',
          lookup_status: 'retry_exhausted',
          provider: 'abuseipdb',
          retry_count: 3,
          retry_exhausted: true,
          failure_category: 'upstream_timeout',
          live_lookup_performed: true,
        },
        {
          observable: 'eicar-hash',
          observable_type: 'file_hash',
          verdict: 'unknown',
          lookup_status: 'circuit_open',
          provider: 'malwarebazaar',
          live_lookup_performed: false,
        },
        {
          observable: 'broken.test',
          observable_type: 'domain',
          verdict: 'unknown',
          lookup_status: 'malformed_response',
          provider: 'otx',
        },
      ],
    }

    render(
      <EnrichmentContextPanel
        enrichment={enrichment}
        onRetryEnrichment={onRetryEnrichment}
        retryEnrichmentError="Temporary backend 503"
      />
    )

    expect(screen.getByText('Attempts: 2')).toBeInTheDocument()
    expect(screen.getByText('virustotal, abuseipdb')).toBeInTheDocument()
    expect(screen.getByText('Rate Limited')).toBeInTheDocument()
    expect(screen.getByText('Retry Exhausted')).toBeInTheDocument()
    expect(screen.getByText('Circuit Breaker Open')).toBeInTheDocument()
    expect(screen.getByText('Malformed Response')).toBeInTheDocument()
    expect(screen.getByText('Retries: 1')).toBeInTheDocument()
    expect(screen.getByText('Retries exhausted (3)')).toBeInTheDocument()
    expect(screen.getByText('http_429_rate_limit')).toBeInTheDocument()
    expect(screen.getByText('upstream_timeout')).toBeInTheDocument()
    expect(screen.getByText(/Manual enrichment retry failed: Temporary backend 503/)).toBeInTheDocument()

    const retryButton = screen.getByRole('button', { name: 'Retry Enrichment' })
    fireEvent.click(retryButton)
    expect(onRetryEnrichment).toHaveBeenCalledTimes(1)
  })

  it('supports manual retry via NormalizedEventView calling retryNormalizedEventEnrichment', async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => ({
        enrichment_id: 'enr-day11-1',
        event_id: 'evt-day11-1',
        enrichment_status: 'enriched',
        attempt_count: 2,
        live_lookup_performed: true,
        observables: [],
      }),
    })
    global.fetch = fetchMock as unknown as typeof fetch

    const event: NormalizedSecurityEvent = {
      event_id: 'evt-day11-1',
      ingestion_id: 'ing-day11-1',
      raw_envelope_id: 101,
      timestamp: '2026-11-28T11:00:00Z',
      source: 'firewall',
      sensor_id: 'fw-01',
      event_category: 'network',
      event_type: 'connection_blocked',
      host: null,
      metadata: {},
      normalization_status: 'normalized',
      warnings: [],
      errors: [],
      enrichment_status: 'failed',
      enrichment: {
        status: 'failed',
        attempt_count: 1,
        observables: [],
        errors: ['Provider timed out'],
      },
    }

    const handleRetry = async (eventId: string) => {
      await apiModule.retryNormalizedEventEnrichment(eventId, true)
    }

    render(<NormalizedEventView normalizedEvent={event} onRetryEnrichment={handleRetry} />)

    fireEvent.click(screen.getByRole('button', { name: 'Retry Enrichment' }))
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/events/normalized/evt-day11-1/enrich?force_retry=true'),
        expect.objectContaining({ method: 'POST' })
      )
    })
  })

  it('fetches and normalizes live backend GET /api/v1/events/threat-intelligence/providers contract', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: { get: () => 'application/json' },
        json: async () => ({
          ti_enabled: true,
          policy: { max_retries: 2, circuit_breaker_threshold: 3 },
          generated_at: '2026-11-28T16:40:00Z',
          providers: [
            {
              provider: 'autosoc.mock_ti_fixture',
              provider_version: '0.1.0',
              enabled: true,
              configured: true,
              operational_state: 'healthy',
              circuit_state: 'closed',
              consecutive_failures: 0,
              total_requests: 5,
              total_failures: 1,
              total_retries: 1,
              last_success_at: '2026-11-28T16:39:50Z',
              last_failure_at: null,
              last_failure_category: 'none',
              cooldown_remaining_seconds: null,
              last_error_summary: null,
            },
            {
              provider: 'virustotal',
              provider_version: 'v3',
              enabled: true,
              configured: false,
              operational_state: 'unavailable',
              circuit_state: 'open',
              consecutive_failures: 3,
              total_requests: 3,
              total_failures: 3,
              total_retries: 2,
              last_success_at: null,
              last_failure_at: '2026-11-28T16:39:55Z',
              last_failure_category: 'timeout',
              cooldown_remaining_seconds: 42.5,
              last_error_summary: 'virustotal unavailable: Bearer secret_leak',
            },
          ],
        }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: async () => ({ detail: 'Not found' }),
      })
    global.fetch = fetchMock as unknown as typeof fetch

    const liveResult = await apiModule.fetchThreatIntelProvidersStatus()
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      expect.stringContaining('/api/v1/events/threat-intelligence/providers'),
      expect.objectContaining({ method: 'GET' })
    )
    expect(liveResult.supported).toBe(true)
    expect(liveResult.ti_enabled).toBe(true)
    expect(liveResult.generated_at).toBe('2026-11-28T16:40:00Z')
    expect(liveResult.providers).toHaveLength(2)

    expect(liveResult.providers[0]).toMatchObject({
      provider_id: 'autosoc.mock_ti_fixture',
      provider_version: '0.1.0',
      enabled: true,
      configured: true,
      status: 'healthy',
      circuit_breaker_state: 'closed',
      retry_count: 1,
      failure_category: null, // 'none' suppressed cleanly
      consecutive_failures: 0,
      total_requests: 5,
      total_failures: 1,
    })
    expect(liveResult.providers[1]).toMatchObject({
      provider_id: 'virustotal',
      provider_version: 'v3',
      enabled: true,
      configured: false,
      status: 'unavailable',
      circuit_breaker_state: 'open',
      retry_count: 2,
      failure_category: 'timeout',
      cooldown_remaining_seconds: 42.5,
      last_error_summary: 'virustotal unavailable: Bearer [REDACTED]',
    })

    render(
      <ProviderStatusPanel
        providers={liveResult.providers}
        tiEnabled={liveResult.ti_enabled}
        generatedAt={liveResult.generated_at}
        backendSupported={liveResult.supported}
      />
    )
    expect(screen.getByText('TI Enabled')).toBeInTheDocument()
    expect(screen.getByText('Not Configured')).toBeInTheDocument()
    expect(screen.getByText('42.5s')).toBeInTheDocument()
    expect(screen.getByText('virustotal unavailable: Bearer [REDACTED]')).toBeInTheDocument()
    expect(screen.queryByText(/secret_leak/)).not.toBeInTheDocument()

    const notFoundResult = await apiModule.fetchThreatIntelProvidersStatus()
    expect(notFoundResult).toEqual({ supported: false, providers: [] })
  })
})
