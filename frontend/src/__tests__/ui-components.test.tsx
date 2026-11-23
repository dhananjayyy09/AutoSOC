import React from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { ServiceStatus } from '@/components/ui/service-status'

describe('Shared UI Components', () => {
  describe('SeverityBadge', () => {
    it.each([
      ['CRITICAL', 'CRITICAL'],
      ['HIGH', 'HIGH'],
      ['MEDIUM', 'MEDIUM'],
      ['LOW', 'LOW'],
      ['INFO', 'INFO'],
    ] as const)('renders %s badge correctly', (level, expectedText) => {
      render(<SeverityBadge level={level} />)
      expect(screen.getByText(expectedText)).toBeInTheDocument()
    })
  })

  describe('ServiceStatus', () => {
    it('renders online service correctly', () => {
      render(<ServiceStatus status="online" serviceName="Database" />)
      expect(screen.getByText('Database')).toBeInTheDocument()
      expect(screen.getByText('Available')).toBeInTheDocument()
      expect(screen.getByText('online')).toBeInTheDocument()
    })

    it('renders warning/degraded service correctly with retry button', () => {
      const onRetry = jest.fn()
      render(<ServiceStatus status="warning" serviceName="Cache Service" onRetry={onRetry} />)
      expect(screen.getByText('Cache Service')).toBeInTheDocument()
      expect(screen.getByText('Degraded')).toBeInTheDocument()
      expect(screen.getByText('warning')).toBeInTheDocument()

      const retryBtn = screen.getByRole('button')
      fireEvent.click(retryBtn)
      expect(onRetry).toHaveBeenCalledTimes(1)
    })

    it('renders offline service with retry callback', () => {
      const onRetry = jest.fn()
      render(<ServiceStatus status="offline" serviceName="Broker" onRetry={onRetry} />)
      expect(screen.getByText('Broker')).toBeInTheDocument()
      expect(screen.getByText('Unavailable')).toBeInTheDocument()

      const retryBtn = screen.getByRole('button')
      fireEvent.click(retryBtn)
      expect(onRetry).toHaveBeenCalledTimes(1)
    })
  })
})
