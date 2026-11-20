import { renderHook, waitFor, act } from '@testing-library/react'
import { useHealthCheck } from '@/hooks/use-health-check'

// Mock the API module
jest.mock('@/lib/api', () => ({
  checkHealth: jest.fn(),
}))

import { checkHealth } from '@/lib/api'

describe('useHealthCheck', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should start in loading state', async () => {
    let resolveHealth: (val: { status: "connected" | "unavailable" }) => void
    const pendingPromise = new Promise<{ status: "connected" | "unavailable" }>((resolve) => {
      resolveHealth = resolve
    })
    ;(checkHealth as jest.Mock).mockReturnValueOnce(pendingPromise)

    const { result } = renderHook(() => useHealthCheck())

    expect(result.current.status).toBe('loading')

    await act(async () => {
      resolveHealth!({ status: 'connected' })
    })
  })

  it('should transition to connected on successful health check', async () => {
    ;(checkHealth as jest.Mock).mockResolvedValueOnce({ status: 'connected' })

    const { result } = renderHook(() => useHealthCheck())

    await waitFor(() => {
      expect(result.current.status).toBe('connected')
    })

    expect(checkHealth).toHaveBeenCalledTimes(1)
  })

  it('should transition to unavailable on failed health check', async () => {
    ;(checkHealth as jest.Mock).mockResolvedValueOnce({ status: 'unavailable' })

    const { result } = renderHook(() => useHealthCheck())

    await waitFor(() => {
      expect(result.current.status).toBe('unavailable')
    })
  })

  it('should retry health check when retry is called', async () => {
    ;(checkHealth as jest.Mock)
      .mockResolvedValueOnce({ status: 'unavailable' })
      .mockResolvedValueOnce({ status: 'connected' })

    const { result } = renderHook(() => useHealthCheck())

    await waitFor(() => {
      expect(result.current.status).toBe('unavailable')
    })

    await act(async () => {
      result.current.retry()
    })

    await waitFor(() => {
      expect(result.current.status).toBe('connected')
    })

    expect(checkHealth).toHaveBeenCalledTimes(2)
  })
})
