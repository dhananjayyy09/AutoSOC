import React from 'react'
import { render, screen } from '@testing-library/react'
import {
  EnrichmentContextPanel,
  ThreatLookupStatusBadge,
  ThreatVerdictBadge,
} from '@/features/events'
import type { EventEnrichmentContext } from '@/types'

// ---------------------------------------------------------------------------
// ThreatLookupStatusBadge
// ---------------------------------------------------------------------------
describe('ThreatLookupStatusBadge', () => {
  it.each([
    ['not_queried', 'Not Queried'],
    ['pending', 'Lookup Pending'],
    ['completed', 'Lookup Completed'],
    ['no_result', 'No Result'],
    ['provider_unavailable', 'Provider Unavailable'],
    ['failed', 'Lookup Failed'],
  ])('renders lookup status %s as %s', (status, expectedLabel) => {
    render(<ThreatLookupStatusBadge status={status} />)
    expect(screen.getByText(expectedLabel)).toBeInTheDocument()
  })

  it('renders unknown fallback for unrecognized status', () => {
    render(<ThreatLookupStatusBadge status="rate_limited_custom" />)
    expect(screen.getByText('Unknown (rate_limited_custom)')).toBeInTheDocument()
  })

  it('keeps no_result visually neutral and provider failure visually distinct from clean', () => {
    const { rerender } = render(<ThreatLookupStatusBadge status="no_result" />)
    expect(screen.getByLabelText('Lookup status: No Result')).toHaveClass('text-slate-300')

    rerender(<ThreatLookupStatusBadge status="provider_unavailable" />)
    expect(screen.getByLabelText('Lookup status: Provider Unavailable')).toHaveClass('text-amber-300')

    rerender(<ThreatLookupStatusBadge status="failed" />)
    expect(screen.getByLabelText('Lookup status: Lookup Failed')).toHaveClass('text-red-300')
  })
})

// ---------------------------------------------------------------------------
// ThreatVerdictBadge
// ---------------------------------------------------------------------------
describe('ThreatVerdictBadge', () => {
  it('renders unknown verdict with neutral styling (never malicious)', () => {
    render(<ThreatVerdictBadge verdict="unknown" />)
    const badge = screen.getByLabelText('Reputation verdict: unknown')
    expect(badge).toHaveTextContent('verdict: unknown')
    expect(badge).toHaveClass('text-slate-300')
    expect(badge).not.toHaveClass('text-red-300')
  })

  it('renders clean, suspicious, and malicious verdicts with distinct tones', () => {
    const { rerender } = render(<ThreatVerdictBadge verdict="clean" />)
    expect(screen.getByLabelText('Reputation verdict: clean')).toHaveClass('text-emerald-300')

    rerender(<ThreatVerdictBadge verdict="suspicious" />)
    expect(screen.getByLabelText('Reputation verdict: suspicious')).toHaveClass('text-amber-300')

    rerender(<ThreatVerdictBadge verdict="malicious" />)
    expect(screen.getByLabelText('Reputation verdict: malicious')).toHaveClass('text-red-300')
  })
})

// ---------------------------------------------------------------------------
// EnrichmentContextPanel – Day 10 TI Presentation
// ---------------------------------------------------------------------------
describe('EnrichmentContextPanel Threat Intelligence Results (mocked data)', () => {
  it('renders provider-backed TI observable fields, evidence, confidence, cached badge, and provenance', () => {
    const enrichment: EventEnrichmentContext = {
      status: 'enriched',
      provider: 'autosoc.ti_coordinator',
      provider_version: '1.0.0',
      live_lookup_performed: true,
      enriched_at: '2026-11-28T10:00:00Z',
      context: {
        network: {
          is_internal_src: false,
          is_internal_dst: true,
        },
        threat_intel: {
          status: 'completed',
          provider: 'abuseipdb',
          sources: ['abuseipdb', 'virustotal'],
          ip_score: 85,
          ip_categories: ['c2', 'scanner'],
          confidence: 0.92,
          cached: true,
          lookup_timestamp: '2026-11-28T10:00:02Z',
          evidence_summary: 'Reported by multiple threat feeds for C2 traffic.',
        },
      },
      observables: [
        {
          observable: '203.0.113.55',
          observable_type: 'ip',
          classification: 'public_routable',
          verdict: 'suspicious',
          provider: 'abuseipdb',
          lookup_status: 'completed',
          lookup_timestamp: '2026-11-28T10:00:02Z',
          evidence_summary: 'Confidence score 85 across 12 reports',
          confidence: 0.85,
          cached: true,
          live_lookup_performed: true,
          source_field: 'source_ip',
          provenance: {
            source_fields: ['source_ip'],
            method: 'live_reputation_lookup',
            evidence: 'Confidence score 85 across 12 reports',
          },
        },
      ],
    }

    render(<EnrichmentContextPanel enrichment={enrichment} />)

    expect(screen.getByText('Live TI Lookup')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /security enrichment context/i })).toBeInTheDocument()
    expect(screen.getByLabelText('Provider-backed threat intelligence summary')).toBeInTheDocument()
    expect(screen.getByText('abuseipdb, virustotal')).toBeInTheDocument()
    expect(screen.getByText('85')).toBeInTheDocument()
    expect(screen.getByText('c2')).toBeInTheDocument()
    expect(screen.getByText('scanner')).toBeInTheDocument()

    // Observable row checks
    expect(screen.getByText('203.0.113.55')).toBeInTheDocument()
    expect(screen.getByText('verdict: suspicious')).toBeInTheDocument()
    expect(screen.getAllByText('Lookup Completed').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('Cached Result').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('Confidence score 85 across 12 reports')).toBeInTheDocument()
    expect(screen.getByText('Confidence: 85%')).toBeInTheDocument()
    expect(screen.getByText('2026-11-28T10:00:02Z')).toBeInTheDocument()
    expect(screen.getByText('source_ip')).toBeInTheDocument()
    expect(screen.getByText('(Live TI)')).toBeInTheDocument()
  })

  it('renders no_result, provider_unavailable, failed, and missing optional fields accurately', () => {
    const enrichment: EventEnrichmentContext = {
      status: 'enriched_partial',
      live_lookup_performed: true,
      observables: [
        {
          observable: 'example.org',
          observable_type: 'domain',
          verdict: 'unknown',
          lookup_status: 'no_result',
          provider: 'virustotal',
          evidence_summary: null,
          confidence: null,
          source_field: null,
          lookup_timestamp: null,
        },
        {
          observable: 'sha256:abcd',
          observable_type: 'file_hash',
          verdict: null,
          lookup_status: 'provider_unavailable',
          provider: 'malwarebazaar',
          evidence_summary: 'Provider circuit breaker open',
        },
        {
          observable: '198.51.100.77',
          observable_type: 'ip',
          verdict: null,
          lookup_status: 'failed',
          provider: 'otx',
          evidence_summary: 'Upstream HTTP 502',
        },
      ],
    }

    render(<EnrichmentContextPanel enrichment={enrichment} />)

    expect(screen.getByText('verdict: unknown')).toBeInTheDocument()
    expect(screen.getByText('No Result')).toBeInTheDocument()
    expect(screen.getByText('Provider Unavailable')).toBeInTheDocument()
    expect(screen.getByText('Lookup Failed')).toBeInTheDocument()
    expect(screen.getByText('No evidence summary')).toBeInTheDocument()
    expect(screen.getByText('Provider circuit breaker open')).toBeInTheDocument()
    expect(screen.getByText('Upstream HTTP 502')).toBeInTheDocument()
  })

  it('distinguishes backend canonical statuses, Fixture TI vs Offline Deterministic, and references', () => {
    const fixtureEnrichment: EventEnrichmentContext = {
      status: 'enriched',
      provider: 'autosoc.deterministic_local',
      provider_version: '0.1.0',
      live_lookup_performed: false,
      context: {
        threat_intel: {
          status: 'completed',
          provider: 'autosoc.mock_ti_fixture',
          cached: false,
          live_lookup_performed: false,
          confidence: 0.92,
          evidence_summary: '203.0.113.99: Controlled RFC 5737 test IP fixture',
          sources: ['autosoc.mock_ti_fixture'],
        },
      },
      observables: [
        {
          observable: '203.0.113.99',
          observable_type: 'ip',
          verdict: 'malicious',
          provider: 'autosoc.mock_ti_fixture',
          lookup_status: 'success',
          confidence: 0.92,
          cached: false,
          live_lookup_performed: false,
          evidence_summary: 'Controlled RFC 5737 test IP fixture; fixture=SYNTH-IP-001',
          references: [{ source_name: 'autosoc_synthetic_ti_fixture', reference_id: 'FIXTURE-IP-001' }],
        },
        {
          observable: '203.0.113.250',
          observable_type: 'ip',
          verdict: 'unknown',
          provider: 'autosoc.mock_ti_fixture',
          lookup_status: 'timeout',
          live_lookup_performed: false,
          evidence_summary: "Provider 'autosoc.mock_ti_fixture' lookup timed out",
        },
      ],
    }

    render(<EnrichmentContextPanel enrichment={fixtureEnrichment} />)
    expect(screen.getByText('Fixture / Mock TI')).toBeInTheDocument()
    expect(screen.queryByText('Live TI Lookup')).not.toBeInTheDocument()
    expect(screen.getAllByText('(Fixture TI)').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('Timed Out')).toBeInTheDocument()
    expect(screen.getByText('[autosoc_synthetic_ti_fixture:FIXTURE-IP-001]')).toBeInTheDocument()
  })
})
