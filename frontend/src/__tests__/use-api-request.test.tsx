import { renderHook, act } from '@testing-library/react'
import { useApiRequest } from '@/hooks/use-api-request'
import { ApiError, isNetworkError } from '@/lib/api'

// ---------------------------------------------------------------------------
// useApiRequest hook tests
// ---------------------------------------------------------------------------
describe('useApiRequest', () => {
  it('starts in idle state', () => {
    const { result } = renderHook(() => useApiRequest(() => Promise.resolve([])))
    expect(result.current.status).toBe('idle')
    expect(result.current.data).toBeNull()
    expect(result.current.error).toBeNull()
  })

  it('transitions to loading then success', async () => {
    const fetcher = jest.fn().mockResolvedValue([{ id: '1' }])
    const { result } = renderHook(() => useApiRequest(fetcher))

    await act(async () => {
      await result.current.execute()
    })

    expect(result.current.status).toBe('success')
    expect(result.current.data).toEqual([{ id: '1' }])
    expect(result.current.error).toBeNull()
  })

  it('transitions to error state on ApiError and sanitizes user message', async () => {
    const fetcher = jest.fn().mockRejectedValue(new ApiError(500, 'Internal Server Error'))
    const { result } = renderHook(() => useApiRequest(fetcher))

    await act(async () => {
      await result.current.execute()
    })

    expect(result.current.status).toBe('error')
    expect(result.current.data).toBeNull()
    // Should show safe user message, not raw "API Error: 500..."
    expect(result.current.error).toMatch(/unexpected error/i)
  })

  it('handles network errors with safe message', async () => {
    const fetcher = jest.fn().mockRejectedValue(new TypeError('Failed to fetch'))
    const { result } = renderHook(() => useApiRequest(fetcher))

    await act(async () => {
      await result.current.execute()
    })

    expect(result.current.status).toBe('error')
    expect(result.current.error).toMatch(/unable to reach/i)
  })

  it('handles generic Error with safe fallback', async () => {
    const fetcher = jest.fn().mockRejectedValue(new Error('Something broke'))
    const { result } = renderHook(() => useApiRequest(fetcher))

    await act(async () => {
      await result.current.execute()
    })

    expect(result.current.status).toBe('error')
    expect(result.current.error).toMatch(/unexpected error/i)
  })

  it('resets error when re-executed successfully', async () => {
    // First fail, then succeed
    const fetcher = jest.fn()
      .mockRejectedValueOnce(new Error('oops'))
      .mockResolvedValueOnce([])

    const { result } = renderHook(() => useApiRequest(fetcher))

    await act(async () => { await result.current.execute() })
    expect(result.current.status).toBe('error')

    await act(async () => { await result.current.execute() })
    expect(result.current.status).toBe('success')
    expect(result.current.error).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Error classification (integration-level sanity)
// ---------------------------------------------------------------------------
describe('isNetworkError', () => {
  it('classifies TypeError with fetch in message', () => {
    expect(isNetworkError(new TypeError('Failed to fetch'))).toBe(true)
  })

  it('does not classify ApiError as network error', () => {
    expect(isNetworkError(new ApiError(500, 'ISE'))).toBe(false)
  })
})
