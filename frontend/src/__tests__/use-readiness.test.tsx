import { renderHook, waitFor, act } from '@testing-library/react'
import { useReadiness } from '@/hooks/use-readiness'
import type { ReadinessResult } from '@/types'

// Mock the API module
jest.mock('@/lib/api', () => ({
  checkReadiness: jest.fn(),
}))

import { checkReadiness } from '@/lib/api'

describe('useReadiness', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should start in loading state', async () => {
    let resolveReadiness: (val: ReadinessResult) => void
    const pendingPromise = new Promise<ReadinessResult>((resolve) => {
      resolveReadiness = resolve
    })
    ;(checkReadiness as jest.Mock).mockReturnValueOnce(pendingPromise)

    const { result } = renderHook(() => useReadiness())

    expect(result.current.state).toBe('loading')

    await act(async () => {
      resolveReadiness!({ state: 'ready' })
    })
  })

  it('should transition to ready when dependencies are healthy', async () => {
    const mockData = {
      status: 'ok',
      postgres: true,
      redis: true,
      qdrant: true,
      kafka: true,
    }
    ;(checkReadiness as jest.Mock).mockResolvedValueOnce({
      state: 'ready',
      data: mockData,
    })

    const { result } = renderHook(() => useReadiness())

    await waitFor(() => {
      expect(result.current.state).toBe('ready')
      expect(result.current.data).toEqual(mockData)
    })

    expect(checkReadiness).toHaveBeenCalledTimes(1)
  })

  it('should transition to degraded when any dependency fails', async () => {
    const degradedData = {
      status: 'degraded',
      postgres: false,
      redis: true,
      qdrant: true,
      kafka: true,
    }
    ;(checkReadiness as jest.Mock).mockResolvedValueOnce({
      state: 'degraded',
      data: degradedData,
    })

    const { result } = renderHook(() => useReadiness())

    await waitFor(() => {
      expect(result.current.state).toBe('degraded')
      expect(result.current.data).toEqual(degradedData)
    })
  })

  it('should transition to unavailable on network failure', async () => {
    ;(checkReadiness as jest.Mock).mockResolvedValueOnce({
      state: 'unavailable',
      error: new Error('Failed to fetch'),
    })

    const { result } = renderHook(() => useReadiness())

    await waitFor(() => {
      expect(result.current.state).toBe('unavailable')
    })
  })

  it('should retry readiness check when retry is called', async () => {
    ;(checkReadiness as jest.Mock)
      .mockResolvedValueOnce({ state: 'unavailable' })
      .mockResolvedValueOnce({
        state: 'ready',
        data: { status: 'ok', postgres: true, redis: true, qdrant: true, kafka: true },
      })

    const { result } = renderHook(() => useReadiness())

    await waitFor(() => {
      expect(result.current.state).toBe('unavailable')
    })

    await act(async () => {
      result.current.retry()
    })

    await waitFor(() => {
      expect(result.current.state).toBe('ready')
    })

    expect(checkReadiness).toHaveBeenCalledTimes(2)
  })
})
