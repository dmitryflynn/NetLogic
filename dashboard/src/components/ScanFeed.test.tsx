import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import ScanFeed from './ScanFeed'
import type { ScanEvent } from '../api/scan'

// A tls event nests everything under results[]; an agent_tool nests HTTP detail under data{};
// a vuln carries an array of CVE objects — all the "hidden behind a broad header" cases.
const events: ScanEvent[] = [
  { type: 'tls', ts: 1700000000, data: { results: [{ grade: 'A', protocols_supported: ['TLSv1.2', 'TLSv1.3'], protocols_deprecated: ['TLSv1.0'] }] } },
  { type: 'agent_tool', ts: 1700000001, data: { tool: 'http_request', ok: true, summary: 'GET /.env -> 403', observation_id: 'obs_3', data: { status: 403, headers: { server: 'Microsoft-IIS/10.0' } } } },
  { type: 'vuln', ts: 1700000002, data: { port: 80, service: 'http', cves: [{ id: 'CVE-2021-31166', cvss: 9.8, description: 'HTTP.sys RCE' }] } },
]

describe('ScanFeed — click to expand technical detail', () => {
  it('reveals the technical panel only after a row is clicked', () => {
    render(<ScanFeed events={events} />)
    expect(screen.getByText(/grade A/)).toBeInTheDocument()             // broad header visible
    expect(screen.queryByText('Technical detail')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText(/grade A/))
    expect(screen.getByText('Technical detail')).toBeInTheDocument()
  })

  it('surfaces array data that used to be hidden (TLS deprecated protocols)', () => {
    render(<ScanFeed events={events} />)
    fireEvent.click(screen.getByText(/grade A/))
    // protocols_deprecated is NOT in the summary header — only the expanded field shows it
    expect(screen.getByText(/TLSv1\.0/)).toBeInTheDocument()
  })

  it('surfaces nested object data for an agent tool row', () => {
    render(<ScanFeed events={events} />)
    fireEvent.click(screen.getByText(/GET \/\.env/))                    // unique to the summary row
    expect(screen.getByText('Technical detail')).toBeInTheDocument()
    expect(screen.getByText(/Microsoft-IIS/)).toBeInTheDocument()       // nested data.headers.server
  })

  it('surfaces the CVE array detail for a finding row', () => {
    render(<ScanFeed events={events} />)
    fireEvent.click(screen.getByText(/CVE-2021-31166 on/))
    expect(screen.getByText(/cvss=9\.8/)).toBeInTheDocument()           // array-of-objects field
  })
})
