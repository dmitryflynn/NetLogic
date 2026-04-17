import { useEffect, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, streamFetch } from './client'

// ── Types ──────────────────────────────────────────────────────────────────────

export interface ScanRequest {
  target: string
  ports: string
  do_tls: boolean
  do_headers: boolean
  do_stack: boolean
  do_dns: boolean
  do_osint: boolean
  do_probe: boolean
  do_takeover: boolean
  do_full: boolean
  cidr: boolean
  timeout: number
  threads: number
  min_cvss: number
  nvd_key?: string
  agent_id?: string
}

export interface JobSummary {
  job_id: string
  org_id: string
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  target: string
  created_at: number
  started_at: number | null
  completed_at: number | null
  result_counts: { ports: number; vulnerabilities: number }
  error: string | null
}

export interface JobDetail extends JobSummary {
  config: ScanRequest
  events?: ScanEvent[]
}

export interface ScanEvent {
  type: string
  // data is typed as PortEvent | VulnEvent | Record<string,unknown> to allow
  // safe narrowing without double-cast (as unknown as X) at call sites.
  data?: PortEvent | VulnEvent | Record<string, unknown>
  message?: string
  ts?: number  // optional server-side timestamp (unix epoch seconds)
}

export interface PortEvent {
  port: number
  state: string
  service: string
  product?: string
  version?: string
  tls?: boolean
}

export interface VulnEvent {
  cve_id: string
  cvss: number
  severity: string
  description: string
  port: number
  service: string
  exploitable?: boolean
  exploit_ref?: string
}

export interface Agent {
  agent_id: string
  org_id: string
  hostname: string
  capabilities: string[]
  version: string
  tags: Record<string, string>
  status: 'online' | 'busy' | 'offline'
  registered_at: number
  last_heartbeat: number | null
  current_job_id: string | null
}

// ── Jobs API ───────────────────────────────────────────────────────────────────

export const useJobs = (limit = 50) =>
  useQuery<JobSummary[]>({
    queryKey: ['jobs', limit],
    queryFn: () => api.get(`/jobs?limit=${limit}`),
    refetchInterval: 5000,
  })

export const useJob = (jobId: string) =>
  useQuery<JobDetail>({
    queryKey: ['job', jobId],
    queryFn: () => api.get(`/jobs/${jobId}`),
    refetchInterval: (q) =>
      q.state.data?.status === 'running' || q.state.data?.status === 'queued'
        ? 2000
        : false,
  })

export const useCreateJob = () => {
  const qc = useQueryClient()
  return useMutation<JobSummary, Error, ScanRequest>({
    mutationFn: (body) => api.post('/jobs', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['jobs'] }),
  })
}

export const useCancelJob = () => {
  const qc = useQueryClient()
  return useMutation<unknown, Error, string>({
    mutationFn: (id) => api.post(`/jobs/${id}/cancel`),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ['jobs'] })
      qc.invalidateQueries({ queryKey: ['job', id] })
    },
  })
}

export const useDeleteJob = () => {
  const qc = useQueryClient()
  return useMutation<unknown, Error, string>({
    mutationFn: (id) => api.delete(`/jobs/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['jobs'] }),
  })
}

// ── Agents API ─────────────────────────────────────────────────────────────────

export const useAgents = () =>
  useQuery<Agent[]>({
    queryKey: ['agents'],
    queryFn: () => api.get('/agents'),
    refetchInterval: 10000,
  })

export const useDeleteAgent = () => {
  const qc = useQueryClient()
  return useMutation<unknown, Error, string>({
    mutationFn: (id) => api.delete(`/agents/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })
}

export interface RegisterAgentRequest {
  hostname: string
  capabilities: string[]
  version: string
  tags: Record<string, string>
}

export interface RegisterAgentResponse {
  agent_id: string
  token: string
  org_id: string
  message: string
}

export const useRegisterAgent = () => {
  const qc = useQueryClient()
  return useMutation<RegisterAgentResponse, Error, RegisterAgentRequest>({
    mutationFn: (body) => api.post('/agents/register', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })
}

// ── SSE stream hook ────────────────────────────────────────────────────────────

/**
 * Consume GET /jobs/{id}/stream via fetch + ReadableStream.
 * EventSource cannot send Authorization headers, so we use raw fetch.
 */
export function useStreamScan(jobId: string | null) {
  const [events, setEvents] = useState<ScanEvent[]>([])
  const [streaming, setStreaming] = useState(false)
  const [done, setDone] = useState(false)
  const abortRef = useRef<AbortController | null>(null)

  useEffect(() => {
    if (!jobId) return

    setEvents([])
    setDone(false)
    setStreaming(true)

    const ctrl = new AbortController()
    abortRef.current = ctrl

    ;(async () => {
      try {
        const res = await streamFetch(`/jobs/${jobId}/stream`, ctrl.signal)
        if (!res.ok || !res.body) { setDone(true); setStreaming(false); return }

        const reader = res.body.getReader()
        const dec = new TextDecoder()
        let buf = ''

        while (true) {
          const { value, done: eof } = await reader.read()
          if (eof) break

          buf += dec.decode(value, { stream: true })
          const chunks = buf.split('\n\n')
          buf = chunks.pop() ?? ''

          for (const chunk of chunks) {
            const line = chunk.trim()
            if (!line.startsWith('data:')) continue
            try {
              const ev: ScanEvent = structuredClone(JSON.parse(line.slice(5).trim()))
              if (ev.type === 'ping') continue
              setEvents((prev) => [...prev, ev])
              if (ev.type === 'done' || ev.type === 'error') {
                setDone(true)
                setStreaming(false)
                return
              }
            } catch { /* skip malformed */ }
          }
        }
      } catch (e) {
        if ((e as Error).name !== 'AbortError') console.error('SSE error', e)
      } finally {
        setDone(true)
        setStreaming(false)
      }
    })()

    return () => ctrl.abort()
  }, [jobId])

  const ports    = events.filter((e) => e.type === 'port').map((e) => e.data as PortEvent)
  const vulns    = events.filter((e) => e.type === 'vuln').map((e) => e.data as VulnEvent)
  const progress = events.filter((e) => e.type === 'progress').at(-1)?.data as { percent?: number } | undefined

  return { events, ports, vulns, progress, streaming, done }
}
