import { ApiClient, checkHealth, checkReadiness } from '@/lib/api'

// Mock fetch globally
global.fetch = jest.fn()

describe('ApiClient', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('get', () => {
    it('should make successful GET request', async () => {
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
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        })
      )
      expect(result).toEqual(mockData)
    })

    it('should normalize endpoints lacking a leading slash', async () => {
      const mockData = { status: 'ok' }
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockData,
      })

      await ApiClient.get('health')

      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:8000/health',
        expect.anything()
      )
    })

    it('should throw error on non-OK response', async () => {
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: async () => ({ detail: 'server error' }),
      })

      await expect(ApiClient.get('/health')).rejects.toThrow('API Error: 500 Internal Server Error')
    })

    it('should handle non-JSON body on non-OK response gracefully', async () => {
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 502,
        statusText: 'Bad Gateway',
        json: async () => {
          throw new Error('Not JSON')
        },
      })

      await expect(ApiClient.get('/health')).rejects.toThrow('API Error: 502 Bad Gateway')
    })

    it('should abort request on timeout', async () => {
      const controller = new AbortController()
      ;(global.fetch as jest.Mock).mockImplementationOnce(() => {
        controller.abort()
        return Promise.reject(new Error('Request aborted'))
      })

      await expect(ApiClient.get('/health', {}, 100)).rejects.toThrow()
    })
  })

  describe('post', () => {
    it('should make successful POST request with serialized JSON body', async () => {
      const payload = { action: 'triage', alertId: '123' }
      const mockResponse = { success: true }

      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      })

      const result = await ApiClient.post('/alerts/triage', payload)

      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:8000/alerts/triage',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify(payload),
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
        })
      )
      expect(result).toEqual(mockResponse)
    })
  })

  describe('put', () => {
    it('should make successful PUT request with serialized JSON body', async () => {
      const payload = { status: 'contained' }
      const mockResponse = { updated: true }

      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      })

      const result = await ApiClient.put('/incidents/123', payload)

      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:8000/incidents/123',
        expect.objectContaining({
          method: 'PUT',
          body: JSON.stringify(payload),
        })
      )
      expect(result).toEqual(mockResponse)
    })
  })

  describe('delete', () => {
    it('should make successful DELETE request', async () => {
      const mockResponse = { deleted: true }

      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      })

      const result = await ApiClient.delete('/threat-hunting/queries/1')

      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:8000/threat-hunting/queries/1',
        expect.objectContaining({
          method: 'DELETE',
        })
      )
      expect(result).toEqual(mockResponse)
    })
  })
})

describe('checkHealth', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should return connected status on successful health check', async () => {
    const mockData = { status: 'ok', service: 'autosoc-backend' }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockData,
    })

    const result = await checkHealth()

    expect(result).toEqual({
      status: 'connected',
      data: mockData,
    })
  })

  it('should return unavailable status on error', async () => {
    ;(global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'))

    const result = await checkHealth()

    expect(result).toEqual({
      status: 'unavailable',
      error: expect.any(Error),
    })
  })
})

describe('checkReadiness', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should return ready state when all dependencies are healthy (HTTP 200)', async () => {
    const mockReadiness = {
      status: 'ok',
      postgres: true,
      redis: true,
      qdrant: true,
      kafka: true,
    }
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => mockReadiness,
    })

    const result = await checkReadiness()

    expect(result.state).toBe('ready')
    expect(result.data).toEqual(mockReadiness)
  })

  it('should return degraded state when backend returns HTTP 503 with degraded detail', async () => {
    const degradedDetail = {
      status: 'degraded',
      postgres: false,
      redis: true,
      qdrant: true,
      kafka: true,
    }
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

  it('should return unavailable state on network failure', async () => {
    ;(global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Connection refused'))

    const result = await checkReadiness()

    expect(result.state).toBe('unavailable')
    expect(result.error).toBeDefined()
  })
})
