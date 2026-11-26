import React from 'react'
import { render, screen } from '@testing-library/react'
import {
  EnrichmentContextPanel,
  EnrichmentStatusBadge,
  NormalizedEventExplorer,
  NormalizedEventView,
} from '@/features/events'
import { queryNormalizedEvents } from '@/lib/api'
import type { EventEnrichmentContext, NormalizedSecurityEvent } from '@/types'

// Mocked API for Explorer table enrichment summary test
jest.mock('@/lib/api', () => {
  const actual = jest.requireActual('@/lib/api')
  return {
    ...actual,
    queryNormalizedEvents: jest.fn(),
  }
})

const mockedQuery = queryNormalizedEvents as jest.MockedFunction<typeof queryNormalizedEvents>

beforeEach(() => {
  jest.clearAllMocks()
})

// ---------------------------------------------------------------------------
// EnrichmentStatusBadge
// ---------------------------------------------------------------------------
describe('EnrichmentStatusBadge', () => {
  it.each([
    ['enriched', 'Enriched'],
    ['partial', 'Partial Enrichment'],
    ['failed', 'Enrichment Failed'],
    ['skipped', 'Skipped'],
    ['not_enriched', 'Not Enriched'],
    [null, 'Not Available'],
  ])('renders status %s with label %s', (status, expectedLabel) => {
    render(<EnrichmentStatusBadge status={status} />)
    expect(screen.getByText(expectedLabel)).toBeInTheDocument()
  })

  it('renders unknown fallback without inventing pending status', () => {
    render(<EnrichmentStatusBadge status="custom_state" />)
    expect(screen.getByText('Unknown (custom_state)')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EnrichmentContextPanel
// ---------------------------------------------------------------------------
describe('EnrichmentContextPanel', () => {
  it('renders honest unavailable state when no enrichment is attached', () => {
    render(<EnrichmentContextPanel enrichment={null} enrichmentStatus={null} />)
    expect(screen.getByText('No enrichment available')).toBeInTheDocument()
  })

  it('renders extracted observables with provenance, provider, classification, and timestamp', () => {
    const enrichment: EventEnrichmentContext = {
      status: 'enriched',
      enriched_at: '2026-11-26T12:00:00Z',
      observables: [
        {
          observable: '198.51.100.44',
          observable_type: 'ip',
          classification: 'external_public',
          provider: 'geoip_internal',
          source_field: 'destination_ip',
          enriched_at: '2026-11-26T12:00:00Z',
        },
      ],
      warnings: [],
      errors: [],
    }

    render(<EnrichmentContextPanel enrichment={enrichment} />)

    expect(screen.getByText('Enriched')).toBeInTheDocument()
    expect(screen.getByText('Enriched: 2026-11-26T12:00:00Z')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.44')).toBeInTheDocument()
    expect(screen.getByText('ip')).toBeInTheDocument()
    expect(screen.getByText('external_public')).toBeInTheDocument()
    expect(screen.getByText('geoip_internal')).toBeInTheDocument()
    expect(screen.getByText('destination_ip')).toBeInTheDocument()
    expect(screen.getByTitle('Extracted from normalized field: destination_ip')).toBeInTheDocument()
  })

  it('handles partial enrichment with warnings and missing optional fields without implying malicious verdict', () => {
    const partial: EventEnrichmentContext = {
      status: 'partial',
      observables: [
        {
          observable: 'example.com',
          observable_type: 'domain',
          classification: null,
          provider: null,
          source_field: null,
          enriched_at: null,
        },
      ],
      warnings: ['Provider timeout during domain lookup'],
      errors: [],
    }

    render(<EnrichmentContextPanel enrichment={partial} />)

    expect(screen.getByText('Partial Enrichment')).toBeInTheDocument()
    expect(screen.getByText('Partial enrichment warnings')).toBeInTheDocument()
    expect(screen.getByText('Provider timeout during domain lookup')).toBeInTheDocument()
    expect(screen.getByText('example.com')).toBeInTheDocument()
    expect(screen.getByText('No verdict')).toBeInTheDocument()
    expect(screen.queryByText(/malicious/i)).not.toBeInTheDocument()
  })

  it('renders enrichment failure errors cleanly', () => {
    const failed: EventEnrichmentContext = {
      status: 'failed',
      observables: [],
      warnings: [],
      errors: ['Enrichment worker unavailable'],
    }

    render(<EnrichmentContextPanel enrichment={failed} />)

    expect(screen.getByText('Enrichment Failed')).toBeInTheDocument()
    expect(screen.getByRole('alert', { name: /enrichment errors/i })).toHaveTextContent(
      'Enrichment worker unavailable'
    )
  })

  it('renders empty observables message when enrichment ran with zero observables', () => {
    render(
      <EnrichmentContextPanel
        enrichment={{ status: 'skipped', observables: [], warnings: [], errors: [] }}
      />
    )
    expect(screen.getByText('No observables extracted')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Integration with NormalizedEventView & NormalizedEventExplorer
// ---------------------------------------------------------------------------
describe('NormalizedEventView & Explorer Enrichment Integration (mocked API)', () => {
  it('keeps normalized fields and enrichment-derived context distinct without exposing raw payloads', () => {
    const event: NormalizedSecurityEvent = {
      event_id: 'evt-enr-1',
      ingestion_id: 'ing-enr-1',
      timestamp: '2026-11-26T11:59:58Z',
      source: 'zeek',
      event_category: 'network',
      event_type: 'network.dns',
      host: 'sensor-02',
      severity: 2,
      metadata: {},
      domain: 'corp.example.net',
      normalization_status: 'normalized',
      enrichment_status: 'enriched',
      enrichment: {
        status: 'enriched',
        observables: [
          {
            observable: 'corp.example.net',
            observable_type: 'domain',
            classification: 'observed_domain',
            provider: 'local_ti',
            source_field: 'domain',
          },
        ],
      },
    }

    render(<NormalizedEventView normalizedEvent={event} />)

    expect(screen.getByRole('region', { name: /normalized security event/i })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /security enrichment context/i })).toBeInTheDocument()
    expect(screen.getByText('observed_domain')).toBeInTheDocument()
    expect(screen.getByText('No raw envelope attached')).toBeInTheDocument()
  })

  it('displays enrichment status badge in NormalizedEventExplorer table rows', async () => {
    mockedQuery.mockResolvedValueOnce({
      items: [
        {
          event_id: 'evt-row-1',
          ingestion_id: 'ing-row-1',
          timestamp: '2026-11-26T12:00:00Z',
          source: 'sysmon',
          event_category: 'process',
          event_type: 'process.create',
          host: 'host-01',
          severity: 3,
          metadata: {},
          normalization_status: 'normalized',
          enrichment_status: 'enriched',
        },
        {
          event_id: 'evt-row-2',
          ingestion_id: 'ing-row-2',
          timestamp: '2026-11-26T12:01:00Z',
          source: 'auditd',
          event_category: 'auth',
          event_type: 'auth.logon',
          host: 'host-02',
          severity: 1,
          metadata: {},
          normalization_status: 'normalized',
          enrichment_status: null,
        },
      ],
      count: 2,
      limit: 20,
      has_more: false,
    })

    render(<NormalizedEventExplorer />)

    expect(await screen.findByText('host-01')).toBeInTheDocument()
    expect(screen.getByLabelText('Enrichment status: Enriched')).toBeInTheDocument()
  })

  it('supports canonical enriched_partial and no_observables badges and context sections', () => {
    const { rerender } = render(<EnrichmentStatusBadge status="enriched_partial" />)
    expect(screen.getByLabelText('Enrichment status: Partial Enrichment')).toBeInTheDocument()

    rerender(<EnrichmentStatusBadge status="no_observables" />)
    expect(screen.getByLabelText('Enrichment status: No Observables')).toBeInTheDocument()

    render(
      <EnrichmentContextPanel
        enrichmentStatus="enriched"
        enrichment={{
          enrichment_id: 'enr-1',
          status: 'enriched',
          provider: 'autosoc.deterministic_local',
          provider_version: '0.1.0',
          live_lookup_performed: false,
          attempt_count: 1,
          enriched_at: '2026-11-26T18:00:00Z',
          context: {
            network: {
              is_internal_src: false,
              is_internal_dst: true,
              is_external_to_internal: true,
              dst_port_well_known: true,
            },
            indicators: {
              domain_tld: 'invalid',
              file_hash_algorithm: 'sha256',
            },
          },
          observables: [
            {
              observable: 'c2.test.invalid',
              original_value: 'C2.TEST.INVALID.',
              observable_type: 'domain',
              classification: 'reserved_or_test_domain',
              verdict: 'unknown',
              provider: 'autosoc.deterministic_local',
              source_field: 'domain',
              enriched_at: '2026-11-26T18:00:00Z',
              provenance: {
                method: 'deterministic_domain_classifier',
                evidence: 'Test domain TLD',
                source_fields: ['domain'],
              },
            },
          ],
        }}
      />
    )

    expect(screen.getByText(/Offline Deterministic/)).toBeInTheDocument()
    expect(screen.getByText(/External -> Internal/)).toBeInTheDocument()
    expect(screen.getByText('c2.test.invalid')).toBeInTheDocument()
    expect(screen.getByText(/orig: C2\.TEST\.INVALID\./)).toBeInTheDocument()
    expect(screen.getByText('verdict: unknown')).toBeInTheDocument()
    expect(screen.getByText('deterministic_domain_classifier')).toBeInTheDocument()
  })
})
