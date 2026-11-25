import {
  ApiClient,
  ApiError,
  checkHealth,
  checkReadiness,
  checkSystemInfo,
  fetchRecentEvents,
  ingestSecurityEvent,
  isAbortError,
  isNetworkError,
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
    const err = new ApiError(409, 'Conflict')
    expect(err.userMessage).toMatch(/HTTP 409/i)
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
  it('fetches bounded recent events from array response', async () => {
    const rows = [
      { ingestion_id: 'ing-1', status: 'accepted', source: 'sysmon' },
      { ingestion_id: 'ing-2', status: 'accepted', source: 'zeek' },
    ]
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({ ok: true, json: async () => rows })

    const res = await fetchRecentEvents(10)
    expect(global.fetch).toHaveBeenCalledWith(
      'http://localhost:8000/api/v1/events?limit=10',
      expect.objectContaining({ method: 'GET' })
    )
    expect(res).toHaveLength(2)
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
