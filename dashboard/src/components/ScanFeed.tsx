import { useEffect, useMemo, useRef, useState } from 'react'
import type { ScanEvent } from '../api/scan'

/** Visual category for filtering + coloring. */
type Cat =
  | 'progress'
  | 'port'
  | 'finding'
  | 'agent'
  | 'module'
  | 'analysis'
  | 'log'
  | 'error'
  | 'system'

interface Row {
  cat: Cat
  label: string
  summary: string
  detail?: string
  tone: string
  badge?: string
}

const CAT_META: Record<Cat, { title: string; chip: string }> = {
  progress: { title: 'Progress', chip: 'bg-accent/15 text-accent border-accent/30' },
  port:     { title: 'Ports',    chip: 'bg-low/15 text-low border-low/30' },
  finding:  { title: 'Findings', chip: 'bg-critical/15 text-critical border-critical/30' },
  agent:    { title: 'AI Agent', chip: 'bg-accent/15 text-accent border-accent/30' },
  module:   { title: 'Modules',  chip: 'bg-medium/15 text-medium border-medium/30' },
  analysis: { title: 'Analysis', chip: 'bg-high/15 text-high border-high/30' },
  log:      { title: 'Logs',     chip: 'bg-elevated text-text-dim border-border' },
  error:    { title: 'Errors',   chip: 'bg-critical/15 text-critical border-critical/30' },
  system:   { title: 'System',   chip: 'bg-elevated text-text-dim border-border' },
}

function str(v: unknown, n = 120): string {
  if (v == null) return ''
  if (typeof v === 'string') return v.length > n ? v.slice(0, n) + '…' : v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  try {
    const s = JSON.stringify(v)
    return s.length > n ? s.slice(0, n) + '…' : s
  } catch {
    return '[…]'
  }
}

function asRec(d: unknown): Record<string, unknown> {
  return d && typeof d === 'object' && !Array.isArray(d) ? (d as Record<string, unknown>) : {}
}

/** Pretty-print JSON for the technical panel (capped so huge payloads stay usable). */
function prettyJson(v: unknown, max = 24000): string {
  try {
    const s = JSON.stringify(v, null, 2)
    if (s.length <= max) return s
    return s.slice(0, max) + `\n… truncated (${s.length.toLocaleString()} chars total)`
  } catch {
    return String(v)
  }
}

/** Compactly render any value (primitive / array / nested object) for the KV view — so arrays and
 *  nested objects (TLS protocols, tech lists, CVE arrays, SPF/DMARC records) are surfaced, not hidden. */
function renderVal(v: unknown): string {
  if (v == null) return ''
  if (Array.isArray(v)) {
    if (v.length === 0) return '[]'
    const allPrimitive = v.every((x) => x == null || typeof x !== 'object')
    if (allPrimitive) return v.map((x) => str(x, 40)).join(', ')
    const head = (v as Record<string, unknown>[]).slice(0, 4).map((o) =>
      o && typeof o === 'object'
        ? `{${Object.entries(o).slice(0, 3).map(([k, x]) => `${k}=${str(x, 24)}`).join(', ')}}`
        : str(o, 40),
    ).join('  ')
    return `[${v.length}] ${head}${v.length > 4 ? ' …' : ''}`
  }
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    const entries = Object.entries(o).filter(([, x]) => x != null).slice(0, 8)
    return `{ ${entries.map(([k, x]) => `${k}: ${str(x, 40)}`).join(', ')}${Object.keys(o).length > 8 ? ' …' : ''} }`
  }
  return String(v)
}

/** Flatten technical fields from any event for a KV view — ALL fields (important ones first),
 *  including arrays and nested objects, so the expansion is real technical detail not a header echo. */
function techFields(e: ScanEvent): { key: string; value: string }[] {
  const out: { key: string; value: string }[] = [{ key: 'type', value: e.type }]
  if (e.message) out.push({ key: 'message', value: e.message })
  if (e.ts != null) out.push({ key: 'timestamp', value: new Date(e.ts * 1000).toISOString() })

  const d = asRec(e.data)
  const prefer = [
    'tool', 'ok', 'summary', 'observation_id', 'high_value', 'step', 'thought',
    'path', 'method', 'status', 'port', 'proto', 'service', 'state', 'product', 'version',
    'cve_id', 'cvss', 'severity', 'error', 'level', 'text', 'percent',
    'host', 'target', 'ip', 'hostname', 'url', 'final_url', 'title', 'grade', 'score',
    'confirmed', 'executed', 'probes_run', 'wordlist', 'checked', 'elapsed_ms',
    'stopped_reason', 'depth_mode', 'high_value_used', 'steps_used', 'requests_used',
  ]
  // Large response strings get a dedicated snippet block below; everything else (incl. results/hits
  // arrays) is surfaced compactly here so no technical field is hidden.
  const skip = new Set(['body', 'response'])
  const orderedKeys = [
    ...prefer.filter((k) => k in d),
    ...Object.keys(d).filter((k) => !prefer.includes(k)),
  ]
  const seen = new Set(out.map((x) => x.key))
  for (const k of orderedKeys) {
    if (seen.has(k) || skip.has(k) || !(k in d) || d[k] == null) continue
    seen.add(k)
    out.push({ key: k, value: renderVal(d[k]) })
  }
  return out
}

function EventTechPanel({ e }: { e: ScanEvent }) {
  const fields = useMemo(() => techFields(e), [e])
  const raw = useMemo(() => prettyJson({
    type: e.type,
    message: e.message ?? null,
    ts: e.ts ?? null,
    data: e.data ?? null,
  }), [e])
  const [copied, setCopied] = useState(false)
  const [tab, setTab] = useState<'fields' | 'json'>('fields')

  async function copyAll() {
    try {
      await navigator.clipboard.writeText(raw)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* ignore */ }
  }

  return (
    <div
      className="mt-2 rounded border border-accent/25 bg-base overflow-hidden"
      onClick={(ev) => ev.stopPropagation()}
    >
      <div className="flex items-center gap-2 px-2.5 py-1.5 border-b border-border/60 bg-elevated/40">
        <span className="text-[10px] font-bold uppercase tracking-wide text-accent">Technical detail</span>
        <div className="flex gap-1 ml-2">
          {(['fields', 'json'] as const).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={`text-[10px] px-2 py-0.5 rounded border ${
                tab === t
                  ? 'border-accent/40 text-accent bg-accent/10'
                  : 'border-border text-text-dim hover:text-text'
              }`}
            >
              {t === 'fields' ? 'Fields' : 'Raw JSON'}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={copyAll}
          className="ml-auto text-[10px] text-text-dim hover:text-accent border border-border rounded px-2 py-0.5"
        >
          {copied ? 'Copied' : 'Copy JSON'}
        </button>
      </div>

      {tab === 'fields' ? (
        <div className="max-h-56 overflow-y-auto">
          <table className="w-full text-[10px]">
            <tbody>
              {fields.map((f) => (
                <tr key={f.key} className="border-b border-border/30 last:border-0 align-top">
                  <td className="px-2.5 py-1 text-text-dim font-mono whitespace-nowrap w-[8.5rem]">{f.key}</td>
                  <td className="px-2.5 py-1 text-text-bright break-all font-mono">{f.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {/* Structured highlights for common payloads */}
          {(() => {
            const d = asRec(e.data)
            const inner = asRec(d.data)
            const body = typeof inner.body === 'string' ? inner.body
              : typeof d.body === 'string' ? d.body
              : typeof d.response === 'string' ? d.response
              : ''
            if (!body) return null
            return (
              <div className="border-t border-border/50 px-2.5 py-2">
                <p className="text-[9px] uppercase tracking-wide text-text-dim mb-1">Response body (snippet)</p>
                <pre className="text-[10px] text-text-dim whitespace-pre-wrap break-all max-h-28 overflow-y-auto font-mono bg-elevated/30 rounded p-2 border border-border/40">
                  {body.slice(0, 4000)}{body.length > 4000 ? '\n…' : ''}
                </pre>
              </div>
            )
          })()}
          {(() => {
            const d = asRec(e.data)
            const results = Array.isArray(d.results) ? d.results as Record<string, unknown>[] : []
            // Only the agent's tool-result shape gets this block; other 'results' arrays (TLS, probes)
            // are shown as compact fields above and in Raw JSON.
            const isToolResults = results.some(
              (r) => r && typeof r === 'object' && ('tool' in r || 'observation_id' in r),
            )
            if (!results.length || !isToolResults) return null
            return (
              <div className="border-t border-border/50 px-2.5 py-2">
                <p className="text-[9px] uppercase tracking-wide text-text-dim mb-1">
                  Tool results this turn ({results.length})
                </p>
                <ul className="space-y-1">
                  {results.map((r, idx) => (
                    <li key={idx} className="text-[10px] font-mono text-text-bright">
                      <span className={r.ok === false ? 'text-medium' : 'text-low'}>
                        {r.ok === false ? '✗' : '✓'}
                      </span>{' '}
                      {str(r.tool, 24)}: {str(r.summary || r.error, 120)}
                      {r.observation_id ? (
                        <span className="text-text-dim"> · {str(r.observation_id, 16)}</span>
                      ) : null}
                    </li>
                  ))}
                </ul>
              </div>
            )
          })()}
          {(() => {
            const d = asRec(e.data)
            const hits = Array.isArray(d.hits) ? d.hits as Record<string, unknown>[] : []
            if (!hits.length) return null
            return (
              <div className="border-t border-border/50 px-2.5 py-2">
                <p className="text-[9px] uppercase tracking-wide text-text-dim mb-1">
                  Dir enum hits ({hits.length})
                </p>
                <ul className="space-y-0.5 font-mono text-[10px]">
                  {hits.slice(0, 30).map((h, idx) => (
                    <li key={idx} className="text-text-bright">
                      <span className="text-accent">{str(h.status, 6)}</span>{' '}
                      {str(h.path, 80)}
                      {h.location ? <span className="text-text-dim"> → {str(h.location, 60)}</span> : null}
                    </li>
                  ))}
                </ul>
              </div>
            )
          })()}
        </div>
      ) : (
        <pre className="max-h-64 overflow-auto p-2.5 text-[10px] font-mono text-text-dim whitespace-pre leading-relaxed">
          {raw}
        </pre>
      )}
    </div>
  )
}

function formatRow(e: ScanEvent): Row {
  const d = asRec(e.data)
  const msg = e.message || ''

  switch (e.type) {
    case 'progress': {
      const pct = d.percent != null ? Math.round(Number(d.percent)) : null
      const status = str(d.status || d.message || msg || 'Working…', 160)
      return {
        cat: 'progress',
        label: pct != null ? `${pct}%` : '…',
        summary: status,
        tone: 'text-accent',
        badge: pct != null ? `${pct}%` : undefined,
      }
    }
    case 'port': {
      const port = d.port ?? '?'
      const proto = d.proto || 'tcp'
      const state = d.state || 'open'
      const svc = str(d.service || '', 40)
      const ver = str(d.version || d.product || d.banner || '', 80)
      return {
        cat: 'port',
        label: 'PORT',
        summary: `${port}/${proto} ${state}${svc ? ` · ${svc}` : ''}${ver ? ` · ${ver}` : ''}`,
        tone: 'text-low',
        badge: String(port),
      }
    }
    case 'vuln': {
      const cves = Array.isArray(d.cves) ? d.cves as Record<string, unknown>[] : null
      if (cves?.length) {
        const ids = cves.map((c) => str(c.id || c.cve_id, 24)).filter(Boolean).join(', ')
        return {
          cat: 'finding',
          label: 'CVE',
          summary: `${ids} on :${d.port ?? '?'}${d.service ? ` (${d.service})` : ''}`,
          detail: str(cves[0]?.description, 240),
          tone: 'text-critical',
          badge: String(cves.length),
        }
      }
      return {
        cat: 'finding',
        label: 'CVE',
        summary: `${str(d.cve_id || d.id, 32)}  ${str(d.title || d.description, 100)}`,
        tone: 'text-critical',
      }
    }
    case 'host':
      return {
        cat: 'system',
        label: 'HOST',
        summary: `${str(d.hostname || d.target, 60)} → ${str(d.ip, 40)}`
          + (d.os_guess ? ` · ${str(d.os_guess, 40)}` : ''),
        tone: 'text-text-bright',
      }
    case 'agent_tool': {
      const tool = str(d.tool || 'tool', 24)
      const ok = d.ok !== false
      const hv = d.high_value ? ' · high-value' : ''
      return {
        cat: 'agent',
        label: 'TOOL',
        summary: `${ok ? '✓' : '✗'} ${tool}: ${str(d.summary || '', 140)}${hv}`,
        detail: d.observation_id ? `obs ${str(d.observation_id, 20)}` : undefined,
        tone: ok ? 'text-accent' : 'text-medium',
        badge: tool,
      }
    }
    case 'agent_turn': {
      const step = d.step ?? '?'
      const thought = str(d.thought || '', 180)
      const results = Array.isArray(d.results) ? d.results as Record<string, unknown>[] : []
      const tools = results.map((r) => str(r.tool || r.summary, 20)).filter(Boolean).slice(0, 6)
      const refused = d.stop_refused ? ` (stop blocked: ${str(d.stop_refused, 80)})` : ''
      return {
        cat: 'agent',
        label: `T${step}`,
        summary: thought || `turn ${step}`,
        detail: tools.length ? `tools: ${tools.join(', ')}${refused}` : refused || undefined,
        tone: 'text-accent',
        badge: `turn ${step}`,
      }
    }
    case 'agent_done':
    case 'ai_agent': {
      const conf = d.confirmed ?? asRec(d).confirmed
      const steps = d.steps_used ?? asRec(d).steps_used
      const hv = d.high_value_used
      const depth = d.depth_mode ? 'depth · ' : ''
      const findings = Array.isArray(d.findings) ? d.findings as Record<string, unknown>[] : []
      const titles = findings.slice(0, 3).map((f) => str(f.title || f.id, 40)).filter(Boolean)
      return {
        cat: 'agent',
        label: 'AGENT',
        summary: `${depth}${conf ?? 0} confirmed · ${hv != null ? `${hv} high-value · ` : ''}${steps ?? '?'} steps`
          + (d.stopped_reason ? ` · ${str(d.stopped_reason, 60)}` : ''),
        detail: titles.length ? titles.join(' · ') : msg || undefined,
        tone: 'text-accent',
      }
    }
    case 'tls': {
      const results = Array.isArray(d.results) ? d.results as Record<string, unknown>[] : []
      const r0 = results[0] || d
      const grade = str(r0.grade, 8)
      const protos = Array.isArray(r0.protocols_supported)
        ? (r0.protocols_supported as string[]).join(', ')
        : ''
      return {
        cat: 'module',
        label: 'TLS',
        summary: `grade ${grade || '?'}${protos ? ` · ${protos}` : ''}`,
        tone: 'text-medium',
      }
    }
    case 'headers': {
      const grade = str(d.grade, 8)
      const score = d.score != null ? `score ${d.score}` : ''
      const missing = Array.isArray(d.headers_missing)
        ? (d.headers_missing as string[]).slice(0, 4).join(', ')
        : ''
      return {
        cat: 'module',
        label: 'HDR',
        summary: [grade && `grade ${grade}`, score, missing && `missing: ${missing}`]
          .filter(Boolean).join(' · ') || 'header audit complete',
        tone: 'text-medium',
      }
    }
    case 'stack': {
      const techs = Array.isArray(d.technologies)
        ? (d.technologies as Record<string, unknown>[]).map((t) => str(t.name, 24)).filter(Boolean)
        : []
      return {
        cat: 'module',
        label: 'STACK',
        summary: techs.slice(0, 6).join(', ') || str(d.cloud_provider || 'stack fingerprint', 80),
        tone: 'text-medium',
      }
    }
    case 'dns': {
      const spf = asRec(d.spf)
      const dmarc = asRec(d.dmarc)
      return {
        cat: 'module',
        label: 'DNS',
        summary: [
          spf.all_mechanism && `SPF ${spf.all_mechanism}`,
          dmarc.policy && `DMARC ${dmarc.policy}`,
        ].filter(Boolean).join(' · ') || str(d.domain, 60) || 'DNS audit',
        tone: 'text-medium',
      }
    }
    case 'osint':
      return { cat: 'module', label: 'OSINT', summary: 'passive recon complete', tone: 'text-medium' }
    case 'takeover':
      return {
        cat: 'module',
        label: 'TAKEOVER',
        summary: Array.isArray(d.vulnerable) && d.vulnerable.length
          ? `${(d.vulnerable as unknown[]).length} vulnerable`
          : 'no takeover candidates',
        tone: 'text-medium',
      }
    case 'service_probes':
    case 'vuln_probes': {
      const confirmed = Array.isArray(d.confirmed) ? d.confirmed as Record<string, unknown>[] : []
      const n = d.probes_run ?? confirmed.length
      const ids = confirmed.map((c) => str(c.cve_id || c.title, 28)).filter(Boolean)
      return {
        cat: 'finding',
        label: e.type === 'vuln_probes' ? 'PROBE' : 'SVC',
        summary: `${n} probes` + (ids.length ? ` · hit: ${ids.join(', ')}` : ''),
        tone: ids.length ? 'text-critical' : 'text-medium',
      }
    }
    case 'service_exploitability':
      return { cat: 'module', label: 'ENUM', summary: 'service exploitability mapped', tone: 'text-medium' }
    case 'web_fingerprint': {
      const notes = Array.isArray(d.notes) ? (d.notes as string[])[0] : ''
      return {
        cat: 'module',
        label: 'WEB',
        summary: str(d.waf || d.app_name || d.title || notes || 'web fingerprint', 140),
        tone: 'text-medium',
      }
    }
    case 'topology':
      return {
        cat: 'module',
        label: 'PATH',
        summary: `${str(d.ip, 40)}${d.hop_count != null ? ` · ${d.hop_count} hops` : ''}`,
        tone: 'text-medium',
      }
    case 'active_validation':
      return {
        cat: 'agent',
        label: 'ACTIVE',
        summary: `${d.confirmed ?? 0} confirmed · ${d.executed ?? 0} executed`,
        tone: 'text-accent',
      }
    case 'fusion': {
      const s = asRec(d.summary)
      return {
        cat: 'analysis',
        label: 'FUSION',
        summary: `${s.confirmed ?? 0} confirmed · ${s.potential ?? 0} potential · ${s.discarded ?? 0} filtered`,
        tone: 'text-high',
      }
    }
    case 'ai':
      return {
        cat: 'analysis',
        label: 'AI',
        summary: str(d.error ? `error: ${d.error}` : (msg || 'analysis update'), 160),
        tone: d.error ? 'text-critical' : 'text-high',
      }
    case 'investigations':
      return { cat: 'analysis', label: 'INV', summary: 'investigations ready', tone: 'text-high' }
    case 'triage':
      return { cat: 'analysis', label: 'TRIAGE', summary: 'findings triaged', tone: 'text-high' }
    case 'log': {
      const level = str(d.level || 'info', 12)
      return {
        cat: level === 'warn' || level === 'error' ? 'error' : 'log',
        label: level.toUpperCase(),
        summary: str(d.text || msg, 200),
        tone: level === 'warn' || level === 'error' ? 'text-medium' : 'text-text-dim',
      }
    }
    case 'error':
      return {
        cat: 'error',
        label: 'ERR',
        summary: str(d.message || msg || e.data, 200),
        tone: 'text-critical',
      }
    case 'done':
      return {
        cat: 'system',
        label: 'DONE',
        summary: str(asRec(e.data).message || msg || 'Scan complete', 120),
        tone: 'text-low',
      }
    case 'info':
      return {
        cat: 'log',
        label: 'INFO',
        summary: str(msg || d.message || d, 180),
        tone: 'text-text-dim',
      }
    default: {
      // Compact module-style for unknown types — never dump raw JSON wall
      const keys = Object.keys(d).slice(0, 4)
      const bits = keys.map((k) => {
        const v = d[k]
        if (v == null || typeof v === 'object') return null
        return `${k}=${str(v, 40)}`
      }).filter(Boolean)
      return {
        cat: 'module',
        label: e.type.replace(/_/g, ' ').slice(0, 12).toUpperCase(),
        summary: bits.length ? bits.join(' · ') : (msg || 'event'),
        detail: keys.length > 4 || Object.values(d).some((v) => typeof v === 'object')
          ? str(d, 280)
          : undefined,
        tone: 'text-text-dim',
      }
    }
  }
}

export default function ScanFeed({
  events,
  live = false,
  defaultOpen = true,
}: {
  events: ScanEvent[]
  /** True while SSE is connected — auto-scroll + live badge. */
  live?: boolean
  defaultOpen?: boolean
}) {
  const bottomRef = useRef<HTMLDivElement>(null)
  const [open, setOpen] = useState(defaultOpen)
  const [autoScroll, setAutoScroll] = useState(true)
  const [filter, setFilter] = useState<Cat | 'all'>('all')
  const [q, setQ] = useState('')
  const [expanded, setExpanded] = useState<Record<number, boolean>>({})

  const rows = useMemo(
    () => events.map((e, i) => ({ i, e, row: formatRow(e) })),
    [events],
  )

  const counts = useMemo(() => {
    const c: Partial<Record<Cat | 'all', number>> = { all: rows.length }
    for (const { row } of rows) c[row.cat] = (c[row.cat] || 0) + 1
    return c
  }, [rows])

  const visible = useMemo(() => {
    const qq = q.trim().toLowerCase()
    return rows.filter(({ row }) => {
      if (filter !== 'all' && row.cat !== filter) return false
      if (!qq) return true
      return (
        row.summary.toLowerCase().includes(qq)
        || row.label.toLowerCase().includes(qq)
        || (row.detail || '').toLowerCase().includes(qq)
      )
    })
  }, [rows, filter, q])

  useEffect(() => {
    if (live && autoScroll && open) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events.length, live, autoScroll, open])

  if (events.length === 0) return null

  const filters: (Cat | 'all')[] = [
    'all', 'progress', 'port', 'finding', 'agent', 'module', 'analysis', 'log', 'error',
  ]

  return (
    <section className="border border-border rounded-lg overflow-hidden bg-panel">
      {/* Header */}
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-3 px-4 py-2.5 bg-elevated/50 border-b border-border hover:bg-elevated text-left"
      >
        <span className="text-text-dim text-[10px] transition-transform" style={{ transform: open ? 'rotate(90deg)' : undefined }}>▶</span>
        <span className="section-title mb-0 normal-case tracking-normal text-[12px] text-text-bright">
          {live ? 'Live event stream' : 'Event log'}
        </span>
        {live && (
          <span className="text-[10px] text-accent animate-pulse flex items-center gap-1">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-accent" /> Live
          </span>
        )}
        <span className="text-[10px] text-text-dim ml-1">{events.length} events</span>
        <span className="ml-auto text-[10px] text-text-dim">{open ? 'Hide' : 'Show'}</span>
      </button>

      {open && (
        <>
          {/* Toolbar */}
          <div className="px-3 py-2 border-b border-border flex flex-wrap items-center gap-2 bg-base/40">
            <div className="flex flex-wrap gap-1">
              {filters.map((f) => {
                const n = counts[f] ?? 0
                if (f !== 'all' && n === 0) return null
                const active = filter === f
                const chip = f === 'all'
                  ? 'bg-elevated text-text border-border'
                  : CAT_META[f].chip
                return (
                  <button
                    key={f}
                    type="button"
                    onClick={() => setFilter(f)}
                    className={`text-[10px] px-2 py-0.5 rounded border ${active ? chip + ' ring-1 ring-accent/40' : 'border-border/60 text-text-dim hover:text-text'}`}
                  >
                    {f === 'all' ? 'All' : CAT_META[f].title}
                    <span className="ml-1 opacity-70">{n}</span>
                  </button>
                )
              })}
            </div>
            <input
              value={q}
              onChange={(ev) => setQ(ev.target.value)}
              placeholder="Filter…"
              className="ml-auto bg-base border border-border rounded px-2 py-0.5 text-[11px] text-text w-36 focus:outline-none focus:border-accent/50"
            />
            {live && (
              <label className="flex items-center gap-1.5 text-[10px] text-text-dim cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={(ev) => setAutoScroll(ev.target.checked)}
                  className="accent-accent"
                />
                Auto-scroll
              </label>
            )}
          </div>

          {/* Rows — click any row for technical detail */}
          <div className="max-h-[28rem] overflow-y-auto divide-y divide-border/40">
            {visible.length === 0 && (
              <p className="text-[11px] text-text-dim px-4 py-6 text-center">No events match this filter.</p>
            )}
            {visible.map(({ i, e, row }) => {
              const isOpen = !!expanded[i]
              return (
                <div
                  key={i}
                  role="button"
                  tabIndex={0}
                  onClick={() => {
                    setExpanded((x) => ({ ...x, [i]: !x[i] }))
                    // Pause auto-scroll when inspecting so the panel doesn't jump away
                    if (live && autoScroll) setAutoScroll(false)
                  }}
                  onKeyDown={(ev) => {
                    if (ev.key === 'Enter' || ev.key === ' ') {
                      ev.preventDefault()
                      setExpanded((x) => ({ ...x, [i]: !x[i] }))
                    }
                  }}
                  className={`px-3 py-1.5 cursor-pointer transition-colors ${
                    isOpen
                      ? 'bg-accent/5 border-l-2 border-l-accent'
                      : 'hover:bg-elevated/40 border-l-2 border-l-transparent'
                  }`}
                  title="Click to show technical detail"
                >
                  <div className="flex items-start gap-2 text-[11px]">
                    <span className={`shrink-0 text-text-dim/60 text-[9px] pt-1 w-3 ${isOpen ? 'text-accent' : ''}`}>
                      {isOpen ? '▾' : '▸'}
                    </span>
                    {e.ts != null && (
                      <span className="text-text-dim/70 shrink-0 tabular-nums w-[4.5rem] pt-0.5">
                        {new Date(e.ts * 1000).toLocaleTimeString()}
                      </span>
                    )}
                    <span className={`shrink-0 text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${CAT_META[row.cat].chip}`}>
                      {row.label}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className={`${row.tone} leading-snug break-words`}>{row.summary}</p>
                      {row.detail && !isOpen && (
                        <p className="text-[10px] text-text-dim/80 truncate mt-0.5">{row.detail}</p>
                      )}
                    </div>
                    {row.badge && (
                      <span className="shrink-0 text-[9px] text-text-dim font-mono pt-0.5">{row.badge}</span>
                    )}
                  </div>
                  {isOpen && <EventTechPanel e={e} />}
                </div>
              )
            })}
            <div ref={bottomRef} />
          </div>

          <div className="px-3 py-1.5 border-t border-border text-[10px] text-text-dim flex justify-between bg-base/30">
            <span>Showing {visible.length} of {events.length} · click a row for technical detail</span>
            <span className="text-text-dim/70">
              {live ? 'Streaming… kept after finish in this Event log' : 'Persisted with the scan job'}
            </span>
          </div>
        </>
      )}
    </section>
  )
}
