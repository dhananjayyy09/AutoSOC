import React from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { NormalizationStatusBadge, NormalizedEventView } from '@/features/events'
import type { IngestedEventRecord, NormalizedSecurityEvent } from '@/types'

// ---------------------------------------------------------------------------
// NormalizationStatusBadge
// ---------------------------------------------------------------------------
describe('NormalizationStatusBadge', () => {
  it.each([
    ['normalized', 'Normalized'],
    ['accepted', 'Accepted (Raw)'],
    ['accepted_with_warnings', 'Accepted with Warnings'],
    ['pending', 'Pending Normalization'],
    ['unsupported', 'Unsupported Source'],
    ['rejected', 'Rejected'],
    ['failed', 'Normalization Failed'],
  ])('renders status %s with label %s', (status, expectedLabel) => {
    render(<NormalizationStatusBadge status={status} />)
    expect(screen.getByText(expectedLabel)).toBeInTheDocument()
  })

  it('renders fallback for unknown status values', () => {
    render(<NormalizationStatusBadge status="custom_stage_xyz" />)
    expect(screen.getByText('Unknown (custom_stage_xyz)')).toBeInTheDocument()
  })

  it('renders fallback when status is null or undefined', () => {
    render(<NormalizationStatusBadge status={null} />)
    expect(screen.getByText('Unknown')).toBeInTheDocument()
  })

  it('renders warnings and errors when provided', () => {
    render(
      <NormalizationStatusBadge
        status="accepted_with_warnings"
        warnings={['timestamp_stale: event older than 30 days']}
        errors={['missing host mapping']}
      />
    )
    expect(screen.getByText('Accepted with Warnings')).toBeInTheDocument()
    expect(screen.getByText('timestamp_stale: event older than 30 days')).toBeInTheDocument()
    expect(screen.getByText('missing host mapping')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// NormalizedEventView
// ---------------------------------------------------------------------------
describe('NormalizedEventView', () => {
  const sampleRawEnvelope: IngestedEventRecord = {
    ingestion_id: 'ing-1111',
    source_type: 'sysmon',
    sensor_id: 'win-sensor-01',
    ingest_time: '2026-11-25T10:00:00Z',
    received_at: '2026-11-25T10:00:01Z',
    raw_hash: 'sha256:abcdef123456',
    payload_size_bytes: 512,
    raw_payload_preview: '<Event><script>alert(1)</script></Event>',
    possible_duplicate: true,
    status: 'accepted',
  }

  const sampleNormalizedEvent: NormalizedSecurityEvent = {
    event_id: 'evt-9999',
    ingestion_id: 'ing-1111',
    timestamp: '2026-11-25T09:59:58Z',
    source: 'sysmon',
    event_category: 'process',
    event_type: 'process.create',
    host: 'workstation-04.corp.local',
    severity: 4,
    raw_event: '<Event>raw</Event>',
    metadata: {},
    user: 'jdoe',
    source_ip: '10.0.0.12',
    destination_ip: '198.51.100.44',
    source_port: 51234,
    destination_port: 443,
    protocol: 'tls',
    process: 'powershell.exe',
    file_hash: 'sha256:00001111',
    domain: 'example.com',
    command_line: 'powershell.exe -NoProfile',
    normalization_status: 'normalized',
  }

  it('renders empty prompt when no event is selected', () => {
    render(<NormalizedEventView />)
    expect(screen.getByText('No event selected')).toBeInTheDocument()
  })

  it('renders raw envelope separately and honest unavailable state when normalized event is absent', () => {
    render(<NormalizedEventView rawEnvelope={sampleRawEnvelope} />)

    expect(screen.getByRole('region', { name: /raw ingestion envelope/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /normalized security event/i })).toBeInTheDocument()

    expect(screen.getByText('ing-1111')).toBeInTheDocument()
    expect(screen.getByText('win-sensor-01')).toBeInTheDocument()
    expect(screen.getByText('512 bytes')).toBeInTheDocument()
    expect(screen.getByText('duplicate raw_hash')).toBeInTheDocument()
    expect(screen.getByText('Accepted (Raw)')).toBeInTheDocument()

    // Safe plain-text rendering (HTML tags shown as text, not injected)
    expect(screen.getByText('<Event><script>alert(1)</script></Event>')).toBeInTheDocument()

    // Honest empty state for missing normalized data
    expect(screen.getByText('Normalized event not available yet')).toBeInTheDocument()
  })

  it('renders full normalized security event fields and severity badge when provided', () => {
    render(
      <NormalizedEventView
        rawEnvelope={sampleRawEnvelope}
        normalizedEvent={sampleNormalizedEvent}
      />
    )

    expect(screen.getByText('Normalized')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
    expect(screen.getByText('evt-9999')).toBeInTheDocument()
    expect(screen.getByText('2026-11-25T09:59:58Z')).toBeInTheDocument()
    expect(screen.getByText('workstation-04.corp.local')).toBeInTheDocument()
    expect(screen.getByText('process')).toBeInTheDocument()
    expect(screen.getByText('process.create')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.12:51234')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.44:443')).toBeInTheDocument()
    expect(screen.getByText('tls')).toBeInTheDocument()
    expect(screen.getByText('powershell.exe')).toBeInTheDocument()
    expect(screen.getByText('powershell.exe -NoProfile')).toBeInTheDocument()
  })

  it('handles missing optional fields and omitted severity gracefully', () => {
    const minimalNormalized: NormalizedSecurityEvent = {
      event_id: 'evt-min',
      ingestion_id: 'ing-1111',
      timestamp: '2026-11-25T10:00:00Z',
      source: 'auditd',
      event_category: 'auth',
      event_type: 'auth.logon',
      host: 'linux-host-01',
      severity: null,
      raw_event: 'type=USER_AUTH',
      metadata: {},
      user: null,
      source_ip: null,
      destination_ip: null,
      source_port: null,
      destination_port: null,
      protocol: null,
      process: null,
      file_hash: null,
      domain: null,
      command_line: null,
    }

    render(<NormalizedEventView rawEnvelope={sampleRawEnvelope} normalizedEvent={minimalNormalized} />)

    expect(screen.getByText('evt-min')).toBeInTheDocument()
    expect(screen.getByText('linux-host-01')).toBeInTheDocument()
    expect(screen.queryByText(/^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$/)).not.toBeInTheDocument()
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(6)
  })

  it('renders loading and error states with retry callback', () => {
    const { rerender } = render(<NormalizedEventView rawEnvelope={sampleRawEnvelope} isLoading />)
    expect(screen.getByText('Loading normalized event data...')).toBeInTheDocument()

    const onRetry = jest.fn()
    rerender(
      <NormalizedEventView
        rawEnvelope={sampleRawEnvelope}
        error="Normalized retrieval endpoint unavailable"
        onRetry={onRetry}
      />
    )
    expect(screen.getByText('Unable to Load Normalized Event')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /try again/i }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })
})
