import React from 'react'
import '@testing-library/jest-dom'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { HealthCheck } from '@/components/health-check'

jest.mock('@/lib/api', () => ({
  checkHealth: jest.fn(),
  checkReadiness: jest.fn(),
}))

import { checkHealth, checkReadiness } from '@/lib/api'

describe('HealthCheck Component', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('displays connected liveness and ready readiness when backend is fully operational', async () => {
    ;(checkHealth as jest.Mock).mockResolvedValue({
      status: 'connected',
      data: { status: 'ok', service: 'autosoc-backend' },
    })
    ;(checkReadiness as jest.Mock).mockResolvedValue({
      state: 'ready',
      data: {
        status: 'ok',
        postgres: true,
        redis: true,
        qdrant: true,
        kafka: true,
      },
    })

    render(<HealthCheck />)

    await waitFor(() => {
      expect(screen.getByText('Backend Connected')).toBeInTheDocument()
      expect(screen.getByText('READY')).toBeInTheDocument()
    })

    expect(screen.getAllByText('Ready').length).toBe(4) // postgres, redis, qdrant, kafka
  })

  it('displays degraded state when an infrastructure dependency fails', async () => {
    ;(checkHealth as jest.Mock).mockResolvedValue({
      status: 'connected',
      data: { status: 'ok', service: 'autosoc-backend' },
    })
    ;(checkReadiness as jest.Mock).mockResolvedValue({
      state: 'degraded',
      data: {
        status: 'degraded',
        postgres: false,
        redis: true,
        qdrant: true,
        kafka: true,
      },
    })

    render(<HealthCheck />)

    await waitFor(() => {
      expect(screen.getByText('Backend Connected')).toBeInTheDocument()
      expect(screen.getByText('DEGRADED / NOT READY')).toBeInTheDocument()
      expect(screen.getByText('Not Ready')).toBeInTheDocument() // postgres not ready
    })
  })

  it('displays unavailable state when backend is offline', async () => {
    ;(checkHealth as jest.Mock).mockResolvedValue({
      status: 'unavailable',
    })
    ;(checkReadiness as jest.Mock).mockResolvedValue({
      state: 'unavailable',
    })

    render(<HealthCheck />)

    await waitFor(() => {
      expect(screen.getByText('Backend Unavailable')).toBeInTheDocument()
      expect(screen.getByText('UNAVAILABLE')).toBeInTheDocument()
    })
  })

  it('calls retry when Refresh button is clicked', async () => {
    const user = userEvent.setup()
    ;(checkHealth as jest.Mock).mockResolvedValue({ status: 'connected' })
    ;(checkReadiness as jest.Mock).mockResolvedValue({
      state: 'ready',
      data: { status: 'ok', postgres: true, redis: true, qdrant: true, kafka: true },
    })

    render(<HealthCheck />)

    await waitFor(() => {
      expect(screen.getByText('READY')).toBeInTheDocument()
    })

    const refreshButton = screen.getByRole('button', { name: /refresh/i })
    await user.click(refreshButton)

    await waitFor(() => {
      expect(checkHealth).toHaveBeenCalledTimes(2)
      expect(checkReadiness).toHaveBeenCalledTimes(2)
    })
  })
})
