import {
  ApiClient,
  ApiError,
  buildNormalizedEventsQueryString,
  checkHealth,
  checkReadiness,
  checkSystemInfo,
  fetchNormalizedEventById,
  fetchNormalizedEvents,
  fetchRecentEvents,
  ingestSecurityEvent,
  isAbortError,
  isNetworkError,
  queryNormalizedEvents,
} from '@/lib/api'
import type { SystemInfoResponse } from '@/types'

// Mock fetch globally
global.fetch = jest.fn()

beforeEach(() => jest.clearAllMocks())

// ---------------------------------------------------------------------------
// ApiError
// ---------------------------------------------------------------------------
describe('ApiError', () => {
  it('should produce a user message for 500', () => {
    const err = new ApiError(500, 'Internal Server Error')
    expect(err.userMessage).toMatch(/unexpected error/i)
  })

  it('should produce a user message for 503', () => {
    const err = new ApiError(503, 'Service Unavailable')
    expect(err.userMessage).toMatch(/unavailable/i)
  })

  it('should produce a user message for 404', () => {
    const err = new ApiError(404, 'Not Found')
    expect(err.userMessage).toMatch(/not found/i)
  })

  it('should produce a user message for 401', () => {
    const err = new ApiError(401, 'Unauthorized')
    expect(err.userMessage).toMatch(/permission/i)
  })

  it('should produce a generic user message for other codes', () => {
    const err = new ApiError(418, "I'm a teapot")
    expect(err.userMessage).toMatch(/HTTP 418/i)
  })
})

// ---------------------------------------------------------------------------
// Error classification helpers
// ---------------------------------------------------------------------------
describe('isAbortError / isNetworkError', () => {
  it('isAbortError returns true for AbortError DOMException', () => {
    const err = new DOMException('The operation was aborted', 'AbortError')
    expect(isAbortError(err)).toBe(true)
    expect(isNetworkError(err)).toBe(true)
  })

  it('isAbortError returns false for generic Error', () => {
    expect(isAbortError(new Error('nope'))).toBe(false)
  })

  it('isNetworkError returns true for TypeError with "fetch" in message', () => {
    expect(isNetworkError(new TypeError('Failed to fetch'))).toBe(true)
  })

  it('isNetworkError returns false for plain Error', () => {
    expect(isNetworkError(new Error('Something else'))).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// ApiClient.get
// ---------------------------------------------------------------------------
describe('ApiClient.get', () => {
  it('should make a successful GET request', async () => {
    const mockData = { status: 'ok', service: 'autosoc-backend' }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockData,
    })

    const result = await ApiClient.get('/health')
    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:8000/health',
      expect.objectContaining({
        method: 'GET',
        headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
      })
    )
    expect(result).toEqual(mockData)
  })

  it('should normalize endpoints lacking a leading slash', async () => {
    const mockData = { status: 'ok' }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => mockData })

    await ApiClient.get('health')

    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:8000/health',
      expect.anything()
    )
  })

  it('should throw ApiError on non-OK response', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      json: async () => ({ detail: 'server error' }),
    })

    await expect(ApiClient.get('/health')).rejects.toThrow('API Error: 500 Internal Server Error')
  })

  it('should throw ApiError even when body is not JSON', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: false,
      status: 502,
      statusText: 'Bad Gateway',
      json: async () => { throw new Error('Not JSON') },
    })

    await expect(ApiClient.get('/health')).rejects.toThrow('API Error: 502 Bad Gateway')
  })

  it('should rethrow on request abort', async () => {
    ;(global.fetch as jest.Mock).mockImplementationOnce(() => {
      return Promise.reject(new DOMException('The operation was aborted', 'AbortError'))
    })

    await expect(ApiClient.get('/health', {}, 100)).rejects.toThrow()
  })
})

// ---------------------------------------------------------------------------
// ApiClient.post / put / delete
// ---------------------------------------------------------------------------
describe('ApiClient.post', () => {
  it('should serialize body as JSON', async () => {
    const payload = { action: 'triage', alertId: '123' }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ success: true }),
    })

    await ApiClient.post('/alerts/triage', payload)

    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:8000/alerts/triage',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify(payload),
      })
    )
  })
})

describe('ApiClient.put', () => {
  it('should send PUT with serialized body', async () => {
    const payload = { status: 'contained' }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ updated: true }),
    })

    await ApiClient.put('/incidents/123', payload)

    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:8000/incidents/123',
      expect.objectContaining({ method: 'PUT', body: JSON.stringify(payload) })
    )
  })
})

describe('ApiClient.delete', () => {
  it('should send DELETE request', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ deleted: true }),
    })

    await ApiClient.delete('/threat-hunting/queries/1')

    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:8000/threat-hunting/queries/1',
      expect.objectContaining({ method: 'DELETE' })
    )
  })
})

// ---------------------------------------------------------------------------
// checkHealth
// ---------------------------------------------------------------------------
describe('checkHealth', () => {
  it('should return connected on success', async () => {
    const mockData = { status: 'ok', service: 'autosoc-backend' }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => mockData })

    const result = await checkHealth()
    expect(result).toEqual({ status: 'connected', data: mockData })
  })

  it('should return unavailable on network error', async () => {
    ;(global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'))

    const result = await checkHealth()
    expect(result.status).toBe('unavailable')
    expect(result.error).toBeDefined()
  })
})

// ---------------------------------------------------------------------------
// checkReadiness
// ---------------------------------------------------------------------------
describe('checkReadiness', () => {
  it('returns ready when all services healthy (HTTP 200)', async () => {
    const mockReadiness = { status: 'ok', postgres: true, redis: true, qdrant: true, kafka: true }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => mockReadiness })

    const result = await checkReadiness()
    expect(result.state).toBe('ready')
    expect(result.data).toEqual(mockReadiness)
  })

  it('returns degraded when any service is false (HTTP 200)', async () => {
    const mockReadiness = { status: 'ok', postgres: true, redis: false, qdrant: true, kafka: true }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => mockReadiness })

    const result = await checkReadiness()
    expect(result.state).toBe('degraded')
    expect(result.data?.redis).toBe(false)
  })

  it('returns degraded on HTTP 503 with detail object', async () => {
    const degradedDetail = { status: 'degraded', postgres: false, redis: true, qdrant: true, kafka: true }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: false,
      status: 503,
      statusText: 'Service Unavailable',
      json: async () => ({ detail: degradedDetail }),
    })

    const result = await checkReadiness()
    expect(result.state).toBe('degraded')
    expect(result.data).toEqual(degradedDetail)
  })

  it('returns unavailable on network failure', async () => {
    ;(global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Connection refused'))

    const result = await checkReadiness()
    expect(result.state).toBe('unavailable')
    expect(result.error).toBeDefined()
  })

  it('returns unavailable on malformed 200 response (null)', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => null })

    const result = await checkReadiness()
    expect(result.state).toBe('unavailable')
  })
})

// ---------------------------------------------------------------------------
// checkSystemInfo
// ---------------------------------------------------------------------------
describe('checkSystemInfo', () => {
  it('returns ok when endpoint responds with system info contract', async () => {
    const mockInfo: SystemInfoResponse = {
      project_name: 'AutoSOC API',
      version: '0.1.0',
      api_version: 'v1',
      environment: 'development',
    }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => mockInfo })

    const result = await checkSystemInfo()
    expect(result.status).toBe('ok')
    expect(result.data).toEqual(mockInfo)
  })

  it('returns unavailable on 404 or missing resource', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      json: async () => ({ message: 'Not found' }),
    })

    const result = await checkSystemInfo()
    expect(result.status).toBe('unavailable')
  })

  it('returns unavailable on network error', async () => {
    ;(global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Network failure'))

    const result = await checkSystemInfo()
    expect(result.status).toBe('unavailable')
  })
})

// ---------------------------------------------------------------------------
// ApiError 422 & validationErrors
// ---------------------------------------------------------------------------
describe('ApiError 422 validationErrors', () => {
  it('returns validation userMessage and extracts field errors', () => {
    const err = new ApiError(422, 'Unprocessable Entity', {
      message: 'Validation error',
      errors: [{ field: 'body -> source_type', message: 'Field required', type: 'missing' }],
    })
    expect(err.userMessage).toMatch(/failed validation/i)
    expect(err.validationErrors).toEqual([
      { field: 'body -> source_type', message: 'Field required', type: 'missing' },
    ])
  })

  it('returns duplicate userMessage for 409 Conflict', () => {
    const err = new ApiError(409, 'Conflict', {
      message: 'Duplicate ingestion_id: event envelope already exists',
    })
    expect(err.userMessage).toMatch(/duplicate ingestion id/i)
  })
})

// ---------------------------------------------------------------------------
// ingestSecurityEvent & fetchRecentEvents (mocked fetch)
// ---------------------------------------------------------------------------
describe('ingestSecurityEvent', () => {
  it('posts payload to /api/v1/events/ingest and returns ingestion response', async () => {
    const mockRes = { ingestion_id: 'ing-123', event_id: 'evt-456', status: 'accepted' }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => mockRes })

    const res = await ingestSecurityEvent({ source_type: 'sysmon', raw_payload: '{}' })
    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:8000/api/v1/events/ingest',
      expect.objectContaining({ method: 'POST' })
    )
    expect(res).toEqual(mockRes)
  })

  it('throws on malformed ingestion response without ingestion_id', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => ({ ok: true }) })

    await expect(ingestSecurityEvent({ source_type: 'sysmon' })).rejects.toThrow(/malformed response/i)
  })
})

describe('fetchRecentEvents', () => {
  it('fetches bounded recent events from canonical backend items envelope', async () => {
    const backendBody = {
      items: [
        {
          ingestion_id: 'ing-1',
          source_type: 'sysmon',
          sensor_id: 'sensor-01',
          ingest_time: '2026-11-25T10:00:00Z',
          raw_hash: 'sha256:' + 'a'.repeat(64),
          payload_size_bytes: 52,
          raw_payload_preview: '<Event />',
          possible_duplicate: false,
          status: 'accepted',
          received_at: '2026-11-25T10:00:01Z',
        },
        {
          ingestion_id: 'ing-2',
          source_type: 'zeek',
          sensor_id: 'sensor-02',
          ingest_time: '2026-11-25T10:01:00Z',
          raw_hash: 'sha256:' + 'b'.repeat(64),
          payload_size_bytes: 40,
          raw_payload_preview: '{"uid":"123"}',
          possible_duplicate: true,
          status: 'accepted',
          received_at: '2026-11-25T10:01:01Z',
        },
      ],
      count: 2,
      limit: 10,
    }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => backendBody })

    const res = await fetchRecentEvents(10)
    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:8000/api/v1/events/ingested?limit=10',
      expect.objectContaining({ method: 'GET' })
    )
    expect(res).toHaveLength(2)
    expect(res[1].possible_duplicate).toBe(true)
  })

  it('normalizes { events: [...] } envelope and enforces limit', async () => {
    const rows = [
      { ingestion_id: 'ing-1', status: 'accepted' },
      { ingestion_id: 'ing-2', status: 'accepted' },
      { ingestion_id: 'ing-3', status: 'accepted' },
    ]
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => ({ events: rows }) })

    const res = await fetchRecentEvents(2)
    expect(res).toHaveLength(2)
    expect(res[0].ingestion_id).toBe('ing-1')
  })
})

// ---------------------------------------------------------------------------
// buildNormalizedEventsQueryString & queryNormalizedEvents (Day 8)
// ---------------------------------------------------------------------------
describe('buildNormalizedEventsQueryString & queryNormalizedEvents', () => {
  it('builds default limit query string and omits unset filters', () => {
    const qs = buildNormalizedEventsQueryString({})
    expect(qs).toBe('limit=20')
  })

  it('includes combined search, filter, sort, and offset parameters', () => {
    const qs = buildNormalizedEventsQueryString({
      limit: 50,
      offset: 50,
      search: '  powershell.exe  ',
      source_type: 'sysmon',
      normalization_status: 'normalized',
      event_category: 'process',
      event_type: '  PROCESS.CREATE ',
      severity: 4,
      start_time: '2026-11-26T00:00:00Z',
      end_time: '2026-11-26T12:00:00Z',
      sort_by: 'normalization_status',
      sort_order: 'asc',
    })
    const parsed = new URLSearchParams(qs)
    expect(parsed.get('limit')).toBe('50')
    expect(parsed.get('offset')).toBe('50')
    expect(parsed.get('search')).toBe('powershell.exe')
    expect(parsed.get('source_type')).toBe('sysmon')
    expect(parsed.get('normalization_status')).toBe('normalized')
    expect(parsed.get('event_category')).toBe('process')
    expect(parsed.get('event_type')).toBe('process.create')
    expect(parsed.get('severity')).toBe('4')
    expect(parsed.get('start_time')).toBe('2026-11-26T00:00:00.000Z'.replace('.000Z', 'Z'))
    expect(parsed.get('end_time')).toBe('2026-11-26T12:00:00Z')
    expect(parsed.get('sort_by')).toBe('normalization_status')
    expect(parsed.get('sort_order')).toBe('asc')

    const clamped = new URLSearchParams(buildNormalizedEventsQueryString({ offset: 99999 }))
    expect(clamped.get('offset')).toBe('10000')
  })

  it('queries /api/v1/events/normalized and maps NormalizedEventListResult', async () => {
    const mockEnvelope = {
      items: [
        {
          event_id: 'evt-1',
          ingestion_id: 'ing-1',
          raw_envelope_id: 1,
          timestamp: '2026-11-26T10:00:00Z',
          source_type: 'sysmon',
          sensor_id: 'sensor-01',
          event_category: 'process',
          event_type: 'process.create',
          host: 'host-01',
          severity: 4,
          metadata: {},
          normalization_status: 'normalized',
          normalization_errors: [],
          normalization_warnings: ['minor warning'],
          created_at: '2026-11-26T10:00:01Z',
        },
      ],
      count: 1,
      limit: 20,
      total: 42,
      offset: 0,
      has_more: true,
    }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockEnvelope,
    })

    const res = await queryNormalizedEvents({ source_type: 'sysmon', severity: 4 })

    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:8000/api/v1/events/normalized?limit=20&source_type=sysmon&severity=4',
      expect.objectContaining({ method: 'GET' })
    )
    expect(res.count).toBe(1)
    expect(res.total).toBe(42)
    expect(res.has_more).toBe(true)
    expect(res.items[0].source).toBe('sysmon')
    expect(res.items[0].warnings).toEqual(['minor warning'])
  })
})

describe('fetchNormalizedEvents & fetchNormalizedEventById', () => {
  it('maps backend NormalizedEventResponse fields into NormalizedSecurityEvent', async () => {
    const backendBody = {
      items: [
        {
          event_id: 'evt-norm-101',
          ingestion_id: 'ing-norm-101',
          raw_envelope_id: 7,
          timestamp: '2026-11-25T10:00:00Z',
          source_type: 'suricata',
          sensor_id: 'sensor-01',
          event_category: 'alert',
          event_type: 'alert.ids',
          host: 'sensor-01',
          user: null,
          source_ip: '192.0.2.10',
          destination_ip: '198.51.100.42',
          source_port: 54321,
          destination_port: 443,
          protocol: 'tcp',
          process: null,
          file_hash: null,
          domain: 'example.invalid',
          command_line: null,
          severity: 4,
          metadata: { pipeline_version: '0.2.0' },
          normalization_status: 'normalized_with_warnings',
          normalization_errors: [],
          normalization_warnings: ['Invalid source_port out of range'],
          created_at: '2026-11-25T10:00:01Z',
        },
      ],
      count: 1,
      limit: 20,
    }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => backendBody })

    const res = await fetchNormalizedEvents(20)
    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:8000/api/v1/events/normalized?limit=20',
      expect.objectContaining({ method: 'GET' })
    )
    expect(res).toHaveLength(1)
    expect(res[0].source).toBe('suricata')
    expect(res[0].normalization_status).toBe('normalized_with_warnings')
    expect(res[0].warnings).toEqual(['Invalid source_port out of range'])
  })

  it('fetches single normalized event by event_id', async () => {
    const backendItem = {
      event_id: 'evt-norm-202',
      ingestion_id: 'ing-norm-202',
      raw_envelope_id: 8,
      timestamp: '2026-11-25T10:05:00Z',
      source_type: 'zeek',
      sensor_id: 'zeek-01',
      event_category: 'network',
      event_type: 'network.dns',
      host: 'zeek-01',
      severity: 1,
      metadata: {},
      normalization_status: 'normalized',
      normalization_errors: [],
      normalization_warnings: [],
      created_at: '2026-11-25T10:05:01Z',
    }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => backendItem })

    const res = await fetchNormalizedEventById('evt-norm-202')
    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:8000/api/v1/events/normalized/evt-norm-202',
      expect.objectContaining({ method: 'GET' })
    )
    expect(res.event_id).toBe('evt-norm-202')
    expect(res.source).toBe('zeek')
  })

  it('maps enrichment context and omits raw_event when provided in NormalizedEventResponse', async () => {
    const backendItem = {
      event_id: 'evt-enr-map',
      ingestion_id: 'ing-enr-map',
      raw_envelope_id: 2,
      timestamp: '2026-11-26T12:00:00Z',
      source_type: 'suricata',
      sensor_id: 'sensor-02',
      event_category: 'network',
      event_type: 'network.connection',
      host: 'edge-01',
      severity: 3,
      metadata: {},
      normalization_status: 'normalized',
      normalization_errors: [],
      normalization_warnings: [],
      enrichment_status: 'partial',
      enrichment: {
        status: 'partial',
        enriched_at: '2026-11-26T12:00:05Z',
        observables: [
          {
            observable: '203.0.113.10',
            observable_type: 'ip',
            classification: 'external',
            provider: 'geoip',
            source_field: 'destination_ip',
          },
        ],
        warnings: ['Provider B unavailable'],
        errors: [],
      },
      created_at: '2026-11-26T12:00:01Z',
    }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => backendItem })

    const res = await fetchNormalizedEventById('evt-enr-map')
    expect(res.enrichment_status).toBe('partial')
    expect(res.enrichment?.observables).toHaveLength(1)
    expect(res.enrichment?.observables?.[0].observable).toBe('203.0.113.10')
    expect(res.enrichment?.warnings).toEqual(['Provider B unavailable'])
    expect(res.raw_event).toBeUndefined()
  })

  it('maps canonical Day 9 backend EventEnrichmentResponse shape with observables and context', async () => {
    const canonicalBackendItem = {
      event_id: 'evt-day9-canon',
      ingestion_id: 'ing-day9-canon',
      raw_envelope_id: 9,
      timestamp: '2026-11-26T18:00:00Z',
      source_type: 'suricata',
      sensor_id: 'sensor-day9',
      event_category: 'alert',
      event_type: 'alert.ids',
      host: 'fw-01',
      severity: 5,
      metadata: {},
      normalization_status: 'normalized',
      normalization_errors: [],
      normalization_warnings: [],
      enrichment_status: 'enriched_partial',
      enrichment: {
        enrichment_id: 'enr-canon-1',
        event_id: 'evt-day9-canon',
        ingestion_id: 'ing-day9-canon',
        provider: 'autosoc.deterministic_local',
        provider_version: '0.1.0',
        enrichment_status: 'enriched_partial',
        live_lookup_performed: false,
        observable_count: 1,
        observables: [
          {
            observable_type: 'ip',
            normalized_value: '198.51.100.42',
            original_value: '198.51.100.42',
            classification: 'documentation_test_ip',
            verdict: 'unknown',
            provenance: {
              provider: 'autosoc.deterministic_local',
              provider_version: '0.1.0',
              source_fields: ['source_ip'],
              method: 'deterministic_ip_classifier',
              evidence: 'RFC 5737 TEST-NET-2',
              live_lookup_performed: false,
            },
          },
        ],
        context: {
          network: {
            is_internal_src: false,
            is_internal_dst: true,
            is_external_to_internal: true,
            dst_port_well_known: true,
          },
          indicators: {
            domain_tld: 'invalid',
            has_file_hash: false,
          },
        },
        warnings: ['malformed domain ignored'],
        errors: [],
        attempt_count: 1,
        enriched_at: '2026-11-26T18:00:02Z',
        created_at: '2026-11-26T18:00:02Z',
        updated_at: '2026-11-26T18:00:02Z',
      },
      created_at: '2026-11-26T18:00:01Z',
    }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => canonicalBackendItem,
    })

    const res = await fetchNormalizedEventById('evt-day9-canon')
    expect(res.enrichment_status).toBe('enriched_partial')
    expect(res.enrichment?.status).toBe('enriched_partial')
    expect(res.enrichment?.provider).toBe('autosoc.deterministic_local')
    expect(res.enrichment?.live_lookup_performed).toBe(false)
    expect(res.enrichment?.context?.network?.is_external_to_internal).toBe(true)
    expect(res.enrichment?.context?.indicators?.domain_tld).toBe('invalid')
    expect(res.enrichment?.observables).toHaveLength(1)
    expect(res.enrichment?.observables?.[0].observable).toBe('198.51.100.42')
    expect(res.enrichment?.observables?.[0].verdict).toBe('unknown')
    expect(res.enrichment?.observables?.[0].source_field).toBe('source_ip')
    expect(res.enrichment?.observables?.[0].enriched_at).toBe('2026-11-26T18:00:02Z')
  })

  it('maps Day 10 provider-backed TI lookup fields when present', async () => {
    const backendItem = {
      event_id: 'evt-ti-map',
      ingestion_id: 'ing-ti-map',
      raw_envelope_id: 10,
      timestamp: '2026-11-28T10:00:00Z',
      source_type: 'suricata',
      sensor_id: 'sensor-01',
      event_category: 'network',
      event_type: 'network.alert',
      host: 'edge-01',
      severity: 4,
      metadata: {},
      normalization_status: 'normalized',
      normalization_errors: [],
      normalization_warnings: [],
      enrichment_status: 'enriched',
      enrichment: {
        status: 'enriched',
        live_lookup_performed: true,
        enriched_at: '2026-11-28T10:00:01Z',
        context: {
          threat_intel: {
            status: 'completed',
            provider: 'abuseipdb',
            cached: true,
            confidence: 0.9,
            lookup_timestamp: '2026-11-28T10:00:02Z',
            evidence_summary: 'Matched known scanner',
            sources: ['abuseipdb'],
          },
        },
        observables: [
          {
            observable_type: 'ip',
            normalized_value: '203.0.113.88',
            original_value: '203.0.113.88',
            classification: 'public_routable',
            verdict: 'suspicious',
            provider: 'abuseipdb',
            lookup_status: 'completed',
            lookup_timestamp: '2026-11-28T10:00:02Z',
            evidence_summary: 'Matched known scanner',
            confidence: 0.9,
            cached: true,
            live_lookup_performed: true,
            provenance: {
              source_fields: ['source_ip'],
              method: 'live_reputation_lookup',
              evidence: 'Matched known scanner',
            },
          },
        ],
      },
      created_at: '2026-11-28T10:00:00Z',
    }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => backendItem })

    const res = await fetchNormalizedEventById('evt-ti-map')
    const obs = res.enrichment?.observables?.[0]
    expect(obs?.lookup_status).toBe('completed')
    expect(obs?.confidence).toBe(0.9)
    expect(obs?.cached).toBe(true)
    expect(obs?.lookup_timestamp).toBe('2026-11-28T10:00:02Z')
    expect(obs?.evidence_summary).toBe('Matched known scanner')
    expect(res.enrichment?.context?.threat_intel?.cached).toBe(true)
    expect(res.enrichment?.context?.threat_intel?.confidence).toBe(0.9)
  })

  it('maps reconciled backend context.threat_intel cache_hits/providers_queried and observable references', async () => {
    const backendItem = {
      event_id: 'evt-ti-reconciled',
      ingestion_id: 'ing-ti-reconciled',
      raw_envelope_id: 11,
      timestamp: '2026-11-28T10:30:00Z',
      source_type: 'suricata',
      sensor_id: 'sensor-02',
      event_category: 'alert',
      event_type: 'alert.ids',
      host: 'fw-02',
      severity: 5,
      metadata: {},
      normalization_status: 'normalized',
      normalization_errors: [],
      normalization_warnings: [],
      enrichment_status: 'enriched',
      enrichment: {
        enrichment_id: 'enr-rec-1',
        event_id: 'evt-ti-reconciled',
        ingestion_id: 'ing-ti-reconciled',
        provider: 'autosoc.deterministic_local',
        provider_version: '0.1.0',
        enrichment_status: 'enriched',
        live_lookup_performed: false,
        observable_count: 1,
        observables: [
          {
            observable_type: 'ip',
            normalized_value: '203.0.113.99',
            original_value: '203.0.113.99',
            classification: 'documentation_test',
            verdict: 'malicious',
            confidence: 0.92,
            lookup_status: 'cache_hit',
            lookup_timestamp: '2026-11-28T10:30:02Z',
            cached: true,
            live_lookup_performed: false,
            evidence_summary: 'Controlled RFC 5737 test IP fixture',
            references: [
              { source_name: 'autosoc_synthetic_ti_fixture', reference_id: 'FIXTURE-IP-001' },
            ],
            provenance: {
              provider: 'autosoc.mock_ti_fixture',
              provider_version: '0.1.0',
              source_fields: ['source_ip'],
              method: 'deterministic_ip_classifier',
              evidence: 'Controlled RFC 5737 test IP fixture',
              live_lookup_performed: false,
            },
          },
        ],
        context: {
          network: { is_internal_src: false },
          threat_intel: {
            status: 'completed',
            providers_queried: ['autosoc.mock_ti_fixture'],
            cache_hits: 1,
            live_lookups: 0,
            max_confidence: 0.92,
            ip_score: 92,
            sources: ['autosoc.mock_ti_fixture'],
          },
        },
        warnings: [],
        errors: [],
        attempt_count: 2,
        enriched_at: '2026-11-28T10:30:02Z',
        created_at: '2026-11-28T10:30:01Z',
        updated_at: '2026-11-28T10:30:02Z',
      },
      created_at: '2026-11-28T10:30:00Z',
    }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => backendItem })

    const res = await fetchNormalizedEventById('evt-ti-reconciled')
    const obs = res.enrichment?.observables?.[0]
    expect(obs?.lookup_status).toBe('cache_hit')
    expect(obs?.cached).toBe(true)
    expect(obs?.live_lookup_performed).toBe(false)
    expect(obs?.references?.[0].reference_id).toBe('FIXTURE-IP-001')
    expect(res.enrichment?.context?.threat_intel?.provider).toBe('autosoc.mock_ti_fixture')
    expect(res.enrichment?.context?.threat_intel?.cached).toBe(true)
    expect(res.enrichment?.context?.threat_intel?.live_lookup_performed).toBe(false)
    expect(res.enrichment?.context?.threat_intel?.confidence).toBe(0.92)
  })
})
