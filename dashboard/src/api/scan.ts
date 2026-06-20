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
  // AI analysis + authenticated scanning (Tier 1/3)
  do_ai?: boolean
  ai_provider?: string
  ai_key?: string
  ai_model?: string
  ai_base_url?: string
  ssh_user?: string
  ssh_key?: string
  ssh_pass?: string
  ssh_port?: number
  // Intelligent agent routing: require capabilities and/or pin to a vantage point
  required_capabilities?: string[]
  agent_selector?: Record<string, string>
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
  kev?: boolean   // CISA Known Exploited Vulnerability
  epss?: number   // EPSS probability of exploitation (0–1)
}

// One adjudicated finding from the fusion gate + AI.
export interface FusionRow {
  subject: string
  port?: number | null
  decision: 'confirmed' | 'potential' | 'discarded'
  impact: 'critical' | 'high' | 'medium' | 'low'
  pinned: boolean
  agreement: number
  rationale?: string
  ai?: { verdict: string; reason: string } | null
  safety_override?: boolean
}

export interface FusionResult {
  confirmed: FusionRow[]
  potential: FusionRow[]
  discarded: FusionRow[]
  summary: {
    signals: number
    confirmed: number
    potential: number
    discarded: number
    ai_adjudicated: number
  }
}

// Aggregated deep-scan sections derived from the event stream.
export interface ScanSections {
  topology?: Record<string, unknown>
  exploitability?: { attributes?: Record<string, unknown>[] }
  webFingerprint?: Record<string, unknown>
  ai?: { markdown?: string; error?: string; provider?: string; model?: string }
  fusion?: FusionResult
  tls?: { results?: Record<string, unknown>[] }
  headers?: Record<string, unknown>
  stack?: Record<string, unknown>
  dns?: Record<string, unknown>
  authenticated?: Record<string, unknown>
  scanDiff?: Record<string, unknown>
}

/** Pull the latest payload for each deep-scan section out of the event list. */
export function extractSections(events: ScanEvent[]): ScanSections {
  const types = ['topology', 'service_exploitability', 'web_fingerprint', 'ai', 'fusion',
    'tls', 'headers', 'stack', 'dns', 'authenticated', 'scan_diff'] as const
  const last = new Map<string, Record<string, unknown>>()
  for (const e of events) {
    if (e.data && types.includes(e.type as typeof types[number])) {
      last.set(e.type, e.data as Record<string, unknown>)
    }
  }
  return {
    topology:       last.get('topology'),
    exploitability: last.get('service_exploitability') as ScanSections['exploitability'],
    webFingerprint: last.get('web_fingerprint'),
    ai:             last.get('ai') as ScanSections['ai'],
    fusion:         last.get('fusion') as unknown as ScanSections['fusion'],
    tls:            last.get('tls') as ScanSections['tls'],
    headers:        last.get('headers'),
    stack:          last.get('stack'),
    dns:            last.get('dns'),
    authenticated:  last.get('authenticated'),
    scanDiff:       last.get('scan_diff'),
  }
}

export interface Agent {
  agent_id: string
  org_id: string
  hostname: string
  capabilities: string[]
  version: string
  tags: Record<string, string>
  status: 'online' | 'busy' | 'offline' | 'disabled'
  disabled: boolean
  concurrency: number
  active_jobs: number
  load: number
  registered_at: number
  last_heartbeat: number | null
  current_job_id: string | null
  token: string
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
  concurrency?: number
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

export const useSetAgentActive = () => {
  const qc = useQueryClient()
  return useMutation<unknown, Error, { id: string; active: boolean }>({
    mutationFn: ({ id, active }) =>
      api.post(`/agents/${id}/${active ? 'activate' : 'deactivate'}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })
}

// ── VDB (Vulnerability Database) ──────────────────────────────────────────────

export interface VdbStatus {
  entries: number
  size_kb: number
  cache_dir: string
  nvd_available: boolean
  synced?: boolean
}

export const useVdbStatus = () =>
  useQuery<VdbStatus>({
    queryKey: ['vdb-status'],
    queryFn: () => api.get('/vdb/status'),
    staleTime: 30_000,
  })

export const useVdbSync = () => {
  const qc = useQueryClient()
  return useMutation<VdbStatus, Error>({
    mutationFn: () => api.post('/vdb/sync'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vdb-status'] }),
  })
}

// ── AI settings ───────────────────────────────────────────────────────────────

export interface AiSettings {
  provider: string
  model: string
  base_url: string
  key_set: boolean
  key_hint: string
  inherits_ai?: boolean   // fusion only: using the AI-analysis config (no separate key)
  providers: string[]
  presets: Record<string, { base_url: string; model: string }>
}

export interface AiSettingsUpdate {
  provider: string
  api_key?: string   // omit/empty to keep the existing stored key
  model?: string
  base_url?: string
}

export const useAiSettings = () =>
  useQuery<AiSettings>({
    queryKey: ['ai-settings'],
    queryFn: () => api.get('/settings/ai'),
    staleTime: 30_000,
  })

export const useSaveAiSettings = () => {
  const qc = useQueryClient()
  return useMutation<AiSettings, Error, AiSettingsUpdate>({
    mutationFn: (body) => api.post('/settings/ai', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ai-settings'] }),
  })
}

export const useTestAiSettings = () =>
  useMutation<{ ok: boolean; error?: string; provider?: string; model?: string }, Error, void>({
    mutationFn: () => api.post('/settings/ai/test'),
  })

// ── Fusion adjudicator config (separate provider/model/key) ────────────────────
export const useFusionSettings = () =>
  useQuery<AiSettings>({
    queryKey: ['fusion-settings'],
    queryFn: () => api.get('/settings/fusion'),
    staleTime: 30_000,
  })

export const useSaveFusionSettings = () => {
  const qc = useQueryClient()
  return useMutation<AiSettings, Error, AiSettingsUpdate>({
    mutationFn: (body) => api.post('/settings/fusion', body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['fusion-settings'] }),
  })
}

export const useTestFusionSettings = () =>
  useMutation<{ ok: boolean; error?: string; provider?: string; model?: string }, Error, void>({
    mutationFn: () => api.post('/settings/fusion/test'),
  })

/**
 * Consume GET /jobs/{id}/stream via fetch + ReadableStream.
 * EventSource cannot send Authorization headers, so we use raw fetch.
 */
export function useStreamScan(jobId: string | null) {
  const [events, setEvents] = useState<ScanEvent[]>([])
  const [streaming, setStreaming] = useState(false)
  const [done, setDone] = useState(false)
  const abortRef = useRef<AbortController | null>(null)
  const retriesRef = useRef(0)

  useEffect(() => {
    if (!jobId) return

    retriesRef.current = 0
    setEvents([])
    setDone(false)
    setStreaming(true)

    let terminated = false
    let cancelled = false

    async function connect(): Promise<void> {
      const ctrl = new AbortController()
      abortRef.current = ctrl

      // Add a 15s connection timeout to prevent hanging forever
      const timeoutId = setTimeout(() => ctrl.abort(), 15_000)

      try {
        const res = await streamFetch(`/jobs/${jobId}/stream`, ctrl.signal)
        clearTimeout(timeoutId)

        if (!res.ok || !res.body) { setDone(true); setStreaming(false); return }

        const reader = res.body.getReader()
        const dec = new TextDecoder()
        let buf = ''

        while (true) {
          const { value, done: eof } = await reader.read()
          if (eof) {
            // Process any remaining data in the buffer before closing
            if (buf.trim()) {
              const line = buf.trim()
              if (line.startsWith('data:')) {
                try {
                  const ev: ScanEvent = JSON.parse(line.slice(5).trim())
                  if (ev.type !== 'ping') {
                    setEvents((prev) => [...prev, ev])
                    if (ev.type === 'done' || ev.type === 'error') {
                      setDone(true)
                      setStreaming(false)
                      terminated = true
                      return
                    }
                  }
                } catch { /* skip malformed */ }
              }
            }
            break
          }

          buf += dec.decode(value, { stream: true })
          // SSE line-delimited parsing: accumulate lines until empty line
          // (event separator). Never split on \n\n inside JSON values.
          let lineEnd: number
          while ((lineEnd = buf.indexOf('\n')) !== -1) {
            const line = buf.slice(0, lineEnd).trimEnd()
            buf = buf.slice(lineEnd + 1)
            if (line === '') {
              // Empty line = event separator — process accumulated data
              // (events are single-line in our backend, so nothing to flush)
              continue
            }
            if (!line.startsWith('data:')) continue
            try {
              const ev: ScanEvent = JSON.parse(line.slice(5).trim())
              if (ev.type === 'ping') continue
              setEvents((prev) => [...prev, ev])
              if (ev.type === 'done' || ev.type === 'error') {
                setDone(true)
                setStreaming(false)
                terminated = true
                return
              }
            } catch { /* skip malformed */ }
          }
        }
      } catch (e) {
        if ((e as Error).name === 'AbortError') return
        console.error('SSE error', e)
      } finally {
        // Don't reconnect if we received a terminal event or user aborted.
        if (!terminated && !cancelled && retriesRef.current < 5) {
          retriesRef.current++
          const delay = Math.min(1000 * Math.pow(2, retriesRef.current), 15_000)
          await new Promise((r) => setTimeout(r, delay))
          if (!cancelled) await connect()
          return
        }
        setDone(true)
        setStreaming(false)
      }
    }

    connect()

    return () => { cancelled = true; abortRef.current?.abort() }
  }, [jobId])

  const ports    = events.filter((e) => e.type === 'port').map((e) => e.data as PortEvent)
  const vulns    = events.filter((e) => e.type === 'vuln').map((e) => e.data as VulnEvent)
  const progress = events.filter((e) => e.type === 'progress').at(-1)?.data as { percent?: number } | undefined

  return { events, ports, vulns, progress, streaming, done }
}
