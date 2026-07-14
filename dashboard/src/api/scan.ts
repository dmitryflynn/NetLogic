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
  // Reasoning engine phases
  do_reason?: boolean
  do_since_last?: boolean
  do_multi_host?: boolean
  do_active_validate?: boolean
  do_ai_driven?: boolean
  do_ai_agent?: boolean
  agent_depth?: boolean
  allow_crash_probes?: boolean
  allow_freeform_proof?: boolean
  allow_exploit_requests?: boolean
  agent_max_steps?: number
  agent_max_requests?: number
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

// Aggregated deep-scan sections derived from the event stream.
// Fusion still runs in the backend for adjudication but is not an operator-facing UI section.
export interface ScanSections {
  topology?: Record<string, unknown>
  exploitability?: { attributes?: Record<string, unknown>[] }
  webFingerprint?: Record<string, unknown>   // includes saas?: SaaSHit[], is_spa?: boolean
  ai?: { markdown?: string; error?: string; provider?: string; model?: string; beyond_cves?: string[] }
  tls?: { results?: Record<string, unknown>[] }
  headers?: Record<string, unknown>
  stack?: Record<string, unknown>
  dns?: Record<string, unknown>
  authenticated?: Record<string, unknown>
  scanDiff?: Record<string, unknown>
  reasoning?: {
    reasoning_enabled?: boolean
    world_modeling_enabled?: boolean
    started_at?: number
    investigation?: {
      persona?: string
      objectives?: ReasoningObjective[]
      goals?: unknown[]
      hypotheses?: ReasoningHypothesis[]
      unknowns?: unknown[]
      contradictions?: { subject?: string; reason?: string; candidates?: string[] }[]
      dead_ends?: { step?: string; reason?: string }[]
    }
    execution?: {
      budget?: Record<string, unknown>
      tokens_used?: number
      probe_history?: unknown[]
      execution_history?: { step?: string; persona?: string; gained?: boolean; rationale?: string }[]
      explanations?: unknown[]
      provenance?: { edges?: unknown[]; nodes?: unknown[] } & Record<string, unknown>
      investigation_plans?: InvestigationPlan[]
      ai_transcript?: AITranscript
    }
    world?: {
      graph?: { nodes?: EvidenceNode[] }
      hosts?: Record<string, unknown>
      observations?: unknown[]
      beliefs?: Record<string, number>
      technology?: unknown[]
      interesting_hosts?: string[]
      interesting_services?: { service?: string; port?: number; reason?: string }[]
      potential_pivots?: unknown[]
    }
  }
  /** Phase 7 change-detection event (only with --since-last). */
  change?: {
    delta?: { added?: Record<string, unknown>[]; removed?: Record<string, unknown>[]; changed?: Record<string, unknown>[] }
    seed?: { hints?: unknown[]; objectives?: string[] }
    report?: string
  }
  /** Active validation event (only with --active-validate): gated safe_active confirmation checks. */
  activeValidation?: {
    confirmed?: number
    executed?: number
    results?: {
      probe?: string; confirms?: string; gated_allowed?: boolean; executed?: boolean
      succeeded?: boolean; denials?: string[]; evidence?: string
      ai_skipped?: boolean; ai_reason?: string
    }[]
    /** Information goals the AI asked for that the deterministic layer won't actively observe. */
    capability_gaps?: { goal?: string; reason?: string; kind?: 'missing_sensor' | 'out_of_scope' | string }[]
  }
  /** Analyst-readable view: raw objectives regrouped into investigations (Q / evidence / conclusion). */
  investigations?: {
    question?: string; subject?: string; kind?: string; conclusion?: string; confidence?: number
    gathered?: number; total_evidence?: number
    adjudicated_by_ai?: boolean; rationale?: string
    evidence?: { name?: string; satisfied?: boolean }[]
  }[]
  /** Architecture Summary: scattered observations synthesised into one plain-English picture (no AI). */
  architecture?: {
    narrative?: string
    stack_kind?: string
    execution_model?: string
    components?: { role?: string; name?: string; evidence?: string; confidence?: number }[]
    attack_surfaces?: string[]
  }
  /** AI overlay OVER the architecture: grounded, prioritised investigation objectives (needs AI key). */
  investigationPlan?: { title?: string; reason?: string; component?: string; priority?: number }[]
  /** Deterministic triage: matched CVEs ranked + bucketed into attention vs low-signal noise (no AI). */
  triage?: {
    attention?: TriageItem[]
    noise?: TriageItem[]
    counts?: { attention?: number; noise?: number; kev?: number; total?: number }
  }
  /** AI investigation agent (do_ai_agent): tool-driven verification + chains. */
  aiAgent?: {
    confirmed?: number
    leads?: number
    steps_used?: number
    requests_used?: number
    high_value_used?: number
    depth_mode?: boolean
    stopped_reason?: string
    findings?: {
      id?: string; title?: string; severity?: string; status?: string
      evidence_refs?: string[]; rationale?: string
    }[]
    chains?: { from?: string; to?: string; why?: string }[]
    turns?: { step?: number; thought?: string; results?: { tool?: string; summary?: string; ok?: boolean }[]; stop?: boolean }[]
    observations?: { observation_id?: string; tool?: string; summary?: string }[]
  }
}

export interface SaaSHit {
  service?: string; category?: string; evidence?: string; severity?: string; detail?: string
}

export interface TriageItem {
  cve?: string; port?: number; service?: string
  cvss?: number; cvss_vector?: string; cwe?: string
  epss?: number; kev?: boolean; exploit_available?: boolean
  reachable?: string; priority?: string; bucket?: string; rationale?: string
  kind?: string; title?: string          // "cve" | "web" (SaaS / exposed-file); title = display label
}

export interface AITranscriptEntry {
  proposal_id?: string
  agent?: string
  kind?: string
  summary?: string
  rationale?: string
  accepted?: boolean
  uncertainty?: string
  stage_failed?: string
  seeded_as?: string
  outcome?: string
}

export interface AITranscript {
  entries?: AITranscriptEntry[]
  summary?: { proposed?: number; accepted?: number; confirmed?: number; refuted?: number; unresolved?: number }
}

export interface InvestigationPlan {
  objective?: string
  goal_reachable?: boolean
  steps?: { action_id?: string; risk_tier?: string; establishes?: string[]; rationale?: string }[]
  unmet_preconditions?: string[]
  max_risk_tier?: string
  score?: number
  rationale?: string
}

export interface ReasoningObjective {
  name?: string
  priority?: number
  satisfied?: boolean
  produced_by?: string
  risk_budget?: string
  source?: { generated_by?: string; reason?: string; confidence?: number }
}

export interface ReasoningHypothesis {
  id?: string
  label?: string
  status?: string
  likelihoods?: Record<string, number>
  entropy?: number
  reason?: string
}

export interface EvidenceObservation {
  kind?: string
  evidence?: string
  source?: string
  reliability?: string
  obs_id?: string
  data?: Record<string, unknown>
}

export interface EvidenceNode {
  id?: string
  kind?: string
  key?: string
  label?: string
  attrs?: Record<string, unknown>
  observations?: EvidenceObservation[]
}

/** Pull the latest payload for each deep-scan section out of the event list. */
export function extractSections(events: ScanEvent[]): ScanSections {
  // 'fusion' intentionally omitted — backend-only adjudication, not rendered in the GUI.
  const types = ['topology', 'service_exploitability', 'web_fingerprint', 'ai',
    'tls', 'headers', 'stack', 'dns', 'authenticated', 'scan_diff', 'reasoning', 'change',
    'active_validation', 'investigations', 'triage', 'architecture', 'investigation_plan',
    'ai_agent'] as const
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
    tls:            last.get('tls') as ScanSections['tls'],
    headers:        last.get('headers'),
    stack:          last.get('stack'),
    dns:            last.get('dns'),
    authenticated:  last.get('authenticated'),
    scanDiff:       last.get('scan_diff'),
    reasoning:      last.get('reasoning') as ScanSections['reasoning'],
    change:         last.get('change') as ScanSections['change'],
    activeValidation: last.get('active_validation') as ScanSections['activeValidation'],
    investigations: (last.get('investigations') as { investigations?: ScanSections['investigations'] } | undefined)?.investigations,
    triage:         last.get('triage') as ScanSections['triage'],
    architecture:   last.get('architecture') as ScanSections['architecture'],
    investigationPlan: (last.get('investigation_plan') as { objectives?: ScanSections['investigationPlan'] } | undefined)?.objectives,
    aiAgent:        last.get('ai_agent') as ScanSections['aiAgent'],
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

// ── Per-target history / posture timeline ───────────────────────────────────────

export interface TargetScan {
  job_id: string
  status: string
  completed_at: number | null
  created_at: number
  progress: number
  open_ports: number[]
  severity: { critical: number; high: number; medium: number; low: number }
  vuln_total: number
  cves: string[]
}

export interface TargetHistory {
  target: string
  scans: TargetScan[]   // completed first (chronological), then running/queued
}

export const useTargetHistory = (target: string | null) =>
  useQuery<TargetHistory>({
    queryKey: ['target-history', target],
    queryFn: () => api.get(`/jobs/history/${encodeURIComponent(target as string)}`),
    enabled: !!target,
    staleTime: 10_000,
    refetchOnMount: true,
    refetchInterval: (query) => {
      // Poll every 5s if any scan is still running
      const data = query.state.data
      if (data && data.scans.some((s) => s.status !== 'completed')) return 5_000
      return false
    },
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

// ── AI settings ───────────────────────────────────────────────────────────────

export interface AiSettings {
  provider: string
  model: string
  base_url: string
  key_set: boolean
  key_hint: string
  inherits_ai?: boolean
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

/** Ask the AI to elaborate on a specific Beyond Known CVEs finding. */
export async function exploreBeyond(jobId: string, finding: string): Promise<{ markdown: string; error?: string }> {
  return api.post(`/jobs/${jobId}/explore-beyond`, { finding })
}

/** On-demand: expand the executive AI report into a much more elaborate technical version. */
export async function technicalAnalysis(jobId: string, executive: string): Promise<{ markdown: string; error?: string }> {
  return api.post(`/jobs/${jobId}/technical-analysis`, { executive })
}

/** Download scan results as a file (JSON, Markdown, or RAW). */
export async function downloadExport(jobId: string, fmt: 'json' | 'md' | 'raw', filename: string): Promise<void> {
  const token = window.Clerk?.session ? await window.Clerk.session.getToken() : null
  const BASE = (import.meta.env.VITE_API_URL ?? '') + '/v1'
  const res = await fetch(`${BASE}/jobs/${jobId}/export?format=${fmt}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) throw new Error(`Export failed: HTTP ${res.status}`)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
