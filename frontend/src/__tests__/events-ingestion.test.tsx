import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { EventIngestionForm, RecentEventsList } from '@/features/events'
import EventsPage from '@/app/(dashboard)/events/page'
import { ApiError, fetchRecentEvents, ingestSecurityEvent } from '@/lib/api'

// Mock API functions only — clearly isolated unit tests (no live backend)
jest.mock('@/lib/api', () => {
  const actual = jest.requireActual('@/lib/api')
  return {
    ...actual,
    ingestSecurityEvent: jest.fn(),
    fetchRecentEvents: jest.fn(),
  }
})

const mockedIngest = ingestSecurityEvent as jest.MockedFunction<typeof ingestSecurityEvent>
const mockedFetchRecent = fetchRecentEvents as jest.MockedFunction<typeof fetchRecentEvents>

beforeEach(() => {
  jest.clearAllMocks()
})

// ---------------------------------------------------------------------------
// EventIngestionForm
// ---------------------------------------------------------------------------
describe('EventIngestionForm (mocked API)', () => {
  it('validates empty input on client side without calling API', async () => {
    render(<EventIngestionForm />)
    fireEvent.click(screen.getByRole('button', { name: /submit event/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Event JSON payload is required.')
    expect(mockedIngest).not.toHaveBeenCalled()
  })

  it('shows syntax error on invalid JSON and preserves user input for correction', async () => {
    render(<EventIngestionForm />)
    const textarea = screen.getByLabelText(/event payload \(json\)/i)

    fireEvent.change(textarea, { target: { value: '{ invalid json' } })
    fireEvent.click(screen.getByRole('button', { name: /submit event/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid json syntax/i)
    expect(textarea).toHaveValue('{ invalid json')
    expect(mockedIngest).not.toHaveBeenCalled()
  })

  it('rejects JSON arrays and non-object primitives', async () => {
    render(<EventIngestionForm />)
    const textarea = screen.getByLabelText(/event payload \(json\)/i)

    fireEvent.change(textarea, { target: { value: '[1, 2, 3]' } })
    fireEvent.click(screen.getByRole('button', { name: /submit event/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/must be a json object/i)
    expect(mockedIngest).not.toHaveBeenCalled()
  })

  it('shows loading state and renders returned ingestion_id and status on valid submission', async () => {
    let resolvePromise!: (value: { ingestion_id: string; event_id: string; status: string }) => void
    mockedIngest.mockImplementationOnce(
      () => new Promise((resolve) => { resolvePromise = resolve })
    )
    const onSuccess = jest.fn()

    render(<EventIngestionForm onSuccess={onSuccess} />)
    const textarea = screen.getByLabelText(/event payload \(json\)/i)
    fireEvent.change(textarea, { target: { value: '{"source_type":"sysmon","sensor_id":"s-1"}' } })
    fireEvent.click(screen.getByRole('button', { name: /submit event/i }))

    expect(screen.getByRole('button', { name: /submitting/i })).toBeDisabled()

    resolvePromise({ ingestion_id: 'ing-999', event_id: 'evt-111', status: 'accepted' })

    const statusBanner = await screen.findByRole('status')
    expect(statusBanner).toHaveTextContent('Event Accepted for Ingestion')
    expect(statusBanner).toHaveTextContent('ing-999')
    expect(statusBanner).toHaveTextContent('evt-111')
    expect(statusBanner).toHaveTextContent('accepted')
    expect(onSuccess).toHaveBeenCalledTimes(1)
  })

  it('displays sanitized 422 validation errors from API', async () => {
    mockedIngest.mockRejectedValueOnce(
      new ApiError(422, 'Unprocessable Entity', {
        message: 'Validation error',
        errors: [{ field: 'body -> sensor_id', message: 'Field required' }],
      })
    )

    render(<EventIngestionForm />)
    fireEvent.change(screen.getByLabelText(/event payload \(json\)/i), {
      target: { value: '{"source_type":"sysmon"}' },
    })
    fireEvent.click(screen.getByRole('button', { name: /submit event/i }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Validation Error')
    expect(alert).toHaveTextContent('body -> sensor_id:')
    expect(alert).toHaveTextContent('Field required')
  })

  it('displays network failure message without leaking internal traces', async () => {
    mockedIngest.mockRejectedValueOnce(new TypeError('Failed to fetch'))

    render(<EventIngestionForm />)
    fireEvent.change(screen.getByLabelText(/event payload \(json\)/i), {
      target: { value: '{"source_type":"sysmon"}' },
    })
    fireEvent.click(screen.getByRole('button', { name: /submit event/i }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Network Error')
    expect(alert).toHaveTextContent(/unable to reach the ingestion backend/i)
  })

  it('clears input and messages when Clear is clicked', async () => {
    render(<EventIngestionForm />)
    const textarea = screen.getByLabelText(/event payload \(json\)/i)
    fireEvent.change(textarea, { target: { value: 'bad' } })
    fireEvent.click(screen.getByRole('button', { name: /submit event/i }))

    expect(await screen.findByRole('alert')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /clear/i }))
    expect(textarea).toHaveValue('')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// RecentEventsList
// ---------------------------------------------------------------------------
describe('RecentEventsList (mocked API)', () => {
  it('renders loading state initially then empty state when no events exist', async () => {
    let resolveList!: (rows: never[]) => void
    mockedFetchRecent.mockImplementationOnce(
      () => new Promise((resolve) => { resolveList = resolve })
    )

    render(<RecentEventsList />)
    expect(screen.getByText(/loading recent ingested events/i)).toBeInTheDocument()

    resolveList([])
    expect(await screen.findByText('No ingested events yet')).toBeInTheDocument()
  })

  it('renders error state when retrieval fails and retries on click', async () => {
    mockedFetchRecent
      .mockRejectedValueOnce(new ApiError(404, 'Not Found'))
      .mockResolvedValueOnce([{ ingestion_id: 'ing-1', status: 'accepted', source: 'zeek' }])

    render(<RecentEventsList />)

    expect(await screen.findByText('Unable to Load Recent Events')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /try again/i }))

    expect(await screen.findByText('ing-1')).toBeInTheDocument()
    expect(mockedFetchRecent).toHaveBeenCalledTimes(2)
  })

  it('renders returned event fields and refreshes when Refresh button is clicked', async () => {
    mockedFetchRecent
      .mockResolvedValueOnce([
        {
          ingestion_id: 'ing-101',
          event_id: 'evt-201',
          source: 'sysmon',
          event_type: 'process.create',
          ingest_time: '2026-11-25T10:00:00Z',
          status: 'accepted',
        },
      ])
      .mockResolvedValueOnce([
        {
          ingestion_id: 'ing-102',
          event_id: 'evt-202',
          source: 'suricata',
          event_type: 'network.alert',
          ingest_time: '2026-11-25T10:05:00Z',
          status: 'queued',
        },
      ])

    render(<RecentEventsList />)

    expect(await screen.findByText('ing-101')).toBeInTheDocument()
    expect(screen.getByText('evt-201')).toBeInTheDocument()
    expect(screen.getByText('sysmon / process.create')).toBeInTheDocument()
    expect(screen.getByText('2026-11-25T10:00:00Z')).toBeInTheDocument()
    expect(screen.getByText('accepted')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /refresh recent events/i }))

    expect(await screen.findByText('ing-102')).toBeInTheDocument()
    expect(screen.getByText('queued')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EventsPage integration (mocked API)
// ---------------------------------------------------------------------------
describe('EventsPage (mocked API)', () => {
  it('refreshes recent events list after a successful submission', async () => {
    mockedFetchRecent
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([
        { ingestion_id: 'ing-new', status: 'accepted', source: 'custom' },
      ])
    mockedIngest.mockResolvedValueOnce({
      ingestion_id: 'ing-new',
      status: 'accepted',
    })

    render(<EventsPage />)

    expect(await screen.findByText('No ingested events yet')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText(/event payload \(json\)/i), {
      target: { value: '{"source_type":"custom","raw_payload":"test"}' },
    })
    fireEvent.click(screen.getByRole('button', { name: /submit event/i }))

    await waitFor(() => {
      expect(screen.getAllByText('ing-new').length).toBeGreaterThanOrEqual(2)
    })
    expect(mockedFetchRecent).toHaveBeenCalledTimes(2)
  })
})
