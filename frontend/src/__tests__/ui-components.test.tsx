import React from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { EmptyState } from '@/components/ui/empty-state'
import { ErrorState } from '@/components/ui/error-state'
import { LoadingState } from '@/components/ui/loading-state'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { ServiceStatus } from '@/components/ui/service-status'

// ---------------------------------------------------------------------------
// EmptyState
// ---------------------------------------------------------------------------
describe('EmptyState', () => {
  it('renders default props', () => {
    render(<EmptyState />)
    expect(screen.getByText('No data available')).toBeInTheDocument()
    expect(screen.getByText('There is currently no data to display in this view.')).toBeInTheDocument()
  })

  it('renders custom title and description', () => {
    render(<EmptyState title="No alerts" description="Alert ingestion is not configured." />)
    expect(screen.getByText('No alerts')).toBeInTheDocument()
    expect(screen.getByText('Alert ingestion is not configured.')).toBeInTheDocument()
  })

  it('renders action button when actionLabel and onAction are provided', () => {
    const onAction = jest.fn()
    render(<EmptyState title="Empty" actionLabel="Refresh" onAction={onAction} />)
    const btn = screen.getByRole('button', { name: 'Refresh' })
    expect(btn).toBeInTheDocument()
    fireEvent.click(btn)
    expect(onAction).toHaveBeenCalledTimes(1)
  })

  it('disables button when isActionLoading is true', () => {
    render(<EmptyState title="Empty" actionLabel="Refresh" onAction={jest.fn()} isActionLoading />)
    expect(screen.getByRole('button')).toBeDisabled()
    expect(screen.getByRole('button')).toHaveTextContent('Loading…')
  })

  it('does not render action button without actionLabel', () => {
    render(<EmptyState title="Empty" />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('has role=status and aria-label', () => {
    render(<EmptyState title="No events" />)
    expect(screen.getByRole('status', { name: 'No events' })).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// ErrorState
// ---------------------------------------------------------------------------
describe('ErrorState', () => {
  it('renders default error state', () => {
    render(<ErrorState />)
    expect(screen.getByText('An error occurred')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toBeInTheDocument()
  })

  it('renders custom title and description', () => {
    render(<ErrorState title="Failed to load alerts" description="Check API connectivity." />)
    expect(screen.getByText('Failed to load alerts')).toBeInTheDocument()
    expect(screen.getByText('Check API connectivity.')).toBeInTheDocument()
  })

  it('renders Try Again button when onRetry is provided', () => {
    const onRetry = jest.fn()
    render(<ErrorState onRetry={onRetry} />)
    const btn = screen.getByRole('button', { name: 'Try again' })
    fireEvent.click(btn)
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('shows Retrying text and disables button when isRetrying', () => {
    render(<ErrorState onRetry={jest.fn()} isRetrying />)
    const btn = screen.getByRole('button')
    expect(btn).toBeDisabled()
    expect(btn).toHaveTextContent('Retrying…')
  })

  it('does not render retry button without onRetry', () => {
    render(<ErrorState />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// LoadingState
// ---------------------------------------------------------------------------
describe('LoadingState', () => {
  it('renders with default loading text', () => {
    render(<LoadingState />)
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })

  it('renders with custom text', () => {
    render(<LoadingState text="Fetching alerts..." />)
    expect(screen.getByText('Fetching alerts...')).toBeInTheDocument()
  })

  it('has aria-live=polite', () => {
    render(<LoadingState />)
    const el = screen.getByRole('status')
    expect(el).toHaveAttribute('aria-live', 'polite')
  })
})

// ---------------------------------------------------------------------------
// SeverityBadge
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// ServiceStatus
// ---------------------------------------------------------------------------
describe('ServiceStatus', () => {
  it('renders online service correctly', () => {
    render(<ServiceStatus status="online" serviceName="Database" />)
    expect(screen.getByText('Database')).toBeInTheDocument()
    expect(screen.getByText('Available')).toBeInTheDocument()
    expect(screen.getByText('online')).toBeInTheDocument()
  })

  it('renders warning/degraded service with retry button', () => {
    const onRetry = jest.fn()
    render(<ServiceStatus status="warning" serviceName="Cache Service" onRetry={onRetry} />)
    expect(screen.getByText('Cache Service')).toBeInTheDocument()
    expect(screen.getByText('Degraded')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button'))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('renders offline service with retry callback', () => {
    const onRetry = jest.fn()
    render(<ServiceStatus status="offline" serviceName="Broker" onRetry={onRetry} />)
    expect(screen.getByText('Unavailable')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button'))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('renders custom description when provided', () => {
    render(<ServiceStatus status="online" serviceName="Postgres" description="All 3 replicas healthy" />)
    expect(screen.getByText('All 3 replicas healthy')).toBeInTheDocument()
  })
})
