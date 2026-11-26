import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { NormalizedEventExplorer } from '@/features/events'
import EventsPage from '@/app/(dashboard)/events/page'
import {
  ApiError,
  fetchNormalizedEventById,
  fetchNormalizedEvents,
  fetchRecentEvents,
  queryNormalizedEvents,
} from '@/lib/api'
import type { NormalizedSecurityEvent } from '@/types'

// Mocked API tests only — no live backend calls
jest.mock('@/lib/api', () => {
  const actual = jest.requireActual('@/lib/api')
  return {
    ...actual,
    queryNormalizedEvents: jest.fn(),
    fetchNormalizedEventById: jest.fn(),
    fetchNormalizedEvents: jest.fn(),
    fetchRecentEvents: jest.fn(),
  }
})

const mockedQuery = queryNormalizedEvents as jest.MockedFunction<typeof queryNormalizedEvents>
const mockedFetchById = fetchNormalizedEventById as jest.MockedFunction<typeof fetchNormalizedEventById>
const mockedFetchNormalized = fetchNormalizedEvents as jest.MockedFunction<typeof fetchNormalizedEvents>
const mockedFetchRecent = fetchRecentEvents as jest.MockedFunction<typeof fetchRecentEvents>

const sampleEvent: NormalizedSecurityEvent = {
  event_id: 'evt-exp-1',
  ingestion_id: 'ing-exp-1',
  timestamp: '2026-11-26T10:00:00Z',
  source: 'sysmon',
  event_category: 'process',
  event_type: 'process.create',
  host: 'ws-01.corp.local',
  severity: 4,
  metadata: {},
  normalization_status: 'normalized',
  warnings: [],
  errors: [],
}

beforeEach(() => {
  jest.clearAllMocks()
  mockedFetchRecent.mockResolvedValue([])
  mockedFetchNormalized.mockResolvedValue([])
})

describe('NormalizedEventExplorer (mocked API)', () => {
  it('renders loading state then empty state when no events exist', async () => {
    let resolveQuery!: (val: {
      items: NormalizedSecurityEvent[]
      count: number
      limit: number
      has_more: boolean
    }) => void
    mockedQuery.mockImplementationOnce(
      () => new Promise((resolve) => { resolveQuery = resolve })
    )

    render(<NormalizedEventExplorer />)
    expect(screen.getByText(/querying normalized security events/i)).toBeInTheDocument()

    resolveQuery({ items: [], count: 0, limit: 20, has_more: false })
    expect(await screen.findByText('No normalized events yet')).toBeInTheDocument()
  })

  it('submits search query to backend and displays result count', async () => {
    mockedQuery
      .mockResolvedValueOnce({ items: [sampleEvent], count: 1, limit: 20, total: 15, has_more: true })
      .mockResolvedValueOnce({ items: [sampleEvent], count: 1, limit: 20, total: 1, has_more: false })

    render(<NormalizedEventExplorer />)

    expect(await screen.findByText('ws-01.corp.local')).toBeInTheDocument()
    expect(screen.getByText(/showing/i)).toHaveTextContent('Showing 1 event of 15 total')

    const searchInput = screen.getByLabelText(/search normalized events/i)
    fireEvent.change(searchInput, { target: { value: 'ws-01' } })
    fireEvent.click(screen.getByRole('button', { name: /^search$/i }))

    await waitFor(() => {
      expect(mockedQuery).toHaveBeenLastCalledWith(
        expect.objectContaining({ search: 'ws-01', offset: 0 })
      )
    })
  })

  it('validates event_type dot-notation client-side and submits valid event_type', async () => {
    mockedQuery.mockResolvedValue({ items: [], count: 0, limit: 20, has_more: false })

    render(<NormalizedEventExplorer />)
    await screen.findByText('No normalized events yet')

    const eventTypeInput = screen.getByLabelText(/filter by event type/i)
    fireEvent.change(eventTypeInput, { target: { value: 'alert.ids; DROP TABLE' } })
    fireEvent.click(screen.getByRole('button', { name: /^search$/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/lowercase dot-notation/i)
    expect(mockedQuery).toHaveBeenCalledTimes(1)

    fireEvent.change(eventTypeInput, { target: { value: 'ALERT.IDS' } })
    fireEvent.click(screen.getByRole('button', { name: /^search$/i }))

    await waitFor(() => {
      expect(mockedQuery).toHaveBeenLastCalledWith(
        expect.objectContaining({ event_type: 'alert.ids', offset: 0 })
      )
    })
  })

  it('sends combined filters and sort controls to backend', async () => {
    mockedQuery.mockResolvedValue({ items: [], count: 0, limit: 20, has_more: false })

    render(<NormalizedEventExplorer />)
    await screen.findByText('No normalized events yet')

    fireEvent.change(screen.getByLabelText(/filter by source type/i), {
      target: { value: 'suricata' },
    })
    fireEvent.change(screen.getByLabelText(/filter by normalization status/i), {
      target: { value: 'failed' },
    })
    fireEvent.change(screen.getByLabelText(/filter by event category/i), {
      target: { value: 'network' },
    })
    fireEvent.change(screen.getByLabelText(/filter by severity/i), {
      target: { value: '5' },
    })
    fireEvent.change(screen.getByLabelText(/sort normalized events by/i), {
      target: { value: 'normalization_status' },
    })
    fireEvent.change(screen.getByLabelText(/sort order/i), {
      target: { value: 'asc' },
    })

    await waitFor(() => {
      expect(mockedQuery).toHaveBeenLastCalledWith(
        expect.objectContaining({
          source_type: 'suricata',
          normalization_status: 'failed',
          event_category: 'network',
          severity: 5,
          sort_by: 'normalization_status',
          sort_order: 'asc',
          offset: 0,
        })
      )
    })

    // Shows no-results empty state when filters are active
    expect(await screen.findByText('No matching normalized events')).toBeInTheDocument()
  })

  it('clears all active filters and resets pagination', async () => {
    mockedQuery.mockResolvedValue({ items: [], count: 0, limit: 20, has_more: false })

    render(<NormalizedEventExplorer />)
    await screen.findByText('No normalized events yet')

    fireEvent.change(screen.getByLabelText(/filter by source type/i), {
      target: { value: 'zeek' },
    })

    await waitFor(() => {
      expect(mockedQuery).toHaveBeenLastCalledWith(expect.objectContaining({ source_type: 'zeek' }))
    })

    fireEvent.click(screen.getAllByRole('button', { name: /clear filters/i })[0])

    await waitFor(() => {
      expect(mockedQuery).toHaveBeenLastCalledWith(
        expect.objectContaining({
          source_type: undefined,
          search: undefined,
          offset: 0,
          sort_by: 'created_at',
          sort_order: 'desc',
        })
      )
    })
  })

  it('handles pagination Next and Previous controls using backend has_more', async () => {
    const page1Items = Array.from({ length: 20 }, (_, i) => ({
      ...sampleEvent,
      event_id: `evt-${i}`,
      ingestion_id: `ing-${i}`,
    }))

    mockedQuery
      .mockResolvedValueOnce({
        items: page1Items,
        count: 20,
        limit: 20,
        total: 25,
        offset: 0,
        has_more: true,
      })
      .mockResolvedValueOnce({
        items: [sampleEvent],
        count: 1,
        limit: 20,
        total: 25,
        offset: 20,
        has_more: false,
      })

    render(<NormalizedEventExplorer />)

    await screen.findByText('evt-0'.replace('evt-0', 'ws-01.corp.local'), { exact: false }).catch(() => null)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /next page/i })).toBeEnabled()
    })
    expect(screen.getByRole('button', { name: /previous page/i })).toBeDisabled()

    fireEvent.click(screen.getByRole('button', { name: /next page/i }))

    await waitFor(() => {
      expect(mockedQuery).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 20, limit: 20 }))
      expect(screen.getByRole('button', { name: /next page/i })).toBeDisabled()
    })
    expect(screen.getByRole('button', { name: /previous page/i })).toBeEnabled()

    fireEvent.click(screen.getByRole('button', { name: /previous page/i }))
    await waitFor(() => {
      expect(mockedQuery).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 0 }))
    })
  })

  it('renders API error state and retries on click', async () => {
    mockedQuery
      .mockRejectedValueOnce(new ApiError(500, 'Internal Server Error'))
      .mockResolvedValueOnce({ items: [sampleEvent], count: 1, limit: 20, has_more: false })

    render(<NormalizedEventExplorer />)

    expect(await screen.findByText('Unable to Query Normalized Events')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /try again/i }))

    expect(await screen.findByText('ws-01.corp.local')).toBeInTheDocument()
  })

  it('guards against reversed time ranges client-side and submits valid UTC bounds', async () => {
    mockedQuery.mockResolvedValue({ items: [], count: 0, limit: 20, has_more: false })

    render(<NormalizedEventExplorer />)
    await screen.findByText('No normalized events yet')

    fireEvent.change(screen.getByLabelText(/start time/i), {
      target: { value: '2026-11-26T12:00' },
    })
    fireEvent.change(screen.getByLabelText(/end time/i), {
      target: { value: '2026-11-26T10:00' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^search$/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/earlier than or equal/i)
    expect(mockedQuery).toHaveBeenCalledTimes(1)

    fireEvent.change(screen.getByLabelText(/end time/i), {
      target: { value: '2026-11-26T14:00' },
    })
    fireEvent.click(screen.getByRole('button', { name: /^search$/i }))

    await waitFor(() => {
      expect(mockedQuery).toHaveBeenLastCalledWith(
        expect.objectContaining({
          start_time: expect.stringMatching(/Z$/),
          end_time: expect.stringMatching(/Z$/),
        })
      )
    })
  })

  it('ignores stale out-of-order query responses', async () => {
    let resolveFirst!: (val: {
      items: NormalizedSecurityEvent[]
      count: number
      limit: number
      has_more: boolean
    }) => void
    let resolveSecond!: (val: {
      items: NormalizedSecurityEvent[]
      count: number
      limit: number
      has_more: boolean
    }) => void

    mockedQuery
      .mockImplementationOnce(() => new Promise((r) => { resolveFirst = r }))
      .mockImplementationOnce(() => new Promise((r) => { resolveSecond = r }))

    render(<NormalizedEventExplorer />)

    fireEvent.change(screen.getByLabelText(/filter by source type/i), {
      target: { value: 'zeek' },
    })

    resolveSecond({
      items: [{ ...sampleEvent, event_id: 'evt-new', host: 'fresh-zeek-host' }],
      count: 1,
      limit: 20,
      has_more: false,
    })
    expect(await screen.findByText('fresh-zeek-host')).toBeInTheDocument()

    resolveFirst({
      items: [{ ...sampleEvent, event_id: 'evt-stale', host: 'stale-initial-host' }],
      count: 1,
      limit: 20,
      has_more: false,
    })

    await waitFor(() => {
      expect(screen.getByText('fresh-zeek-host')).toBeInTheDocument()
      expect(screen.queryByText('stale-initial-host')).not.toBeInTheDocument()
    })
  })
})

describe('EventsPage Explorer Detail Selection (mocked API)', () => {
  it('loads normalized detail record when selecting an event in NormalizedEventExplorer', async () => {
    mockedQuery.mockResolvedValueOnce({ items: [sampleEvent], count: 1, limit: 20, has_more: false })
    mockedFetchById.mockResolvedValueOnce({
      ...sampleEvent,
      process: 'powershell.exe',
      protocol: 'tls',
    })

    render(<EventsPage />)

    const inspectBtn = await screen.findByRole('button', { name: /inspect normalized event evt-exp-1/i })
    fireEvent.click(inspectBtn)

    await waitFor(() => {
      expect(mockedFetchById).toHaveBeenCalledWith('evt-exp-1')
    })
    expect(await screen.findByText('powershell.exe')).toBeInTheDocument()
  })
})
