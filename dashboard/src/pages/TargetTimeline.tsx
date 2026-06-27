import { useParams, Link } from 'react-router-dom'
import { useTargetHistory, downloadExport, type TargetScan } from '../api/scan'

const SEVS = ['critical', 'high', 'medium', 'low'] as const

function fmtDate(ts: number | null): string {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

function SeverityBadges({ sev, status }: { sev: TargetScan['severity']; status?: string }) {
  if (status && status !== 'completed') {
    return <span className="text-text-dim text-[11px] italic">{status}…</span>
  }
  const any = SEVS.some((s) => sev[s] > 0)
  if (!any) return <span className="text-low text-[11px]">clean</span>
  return (
    <span className="flex items-center gap-1.5">
      {SEVS.filter((s) => sev[s] > 0).map((s) => (
        <span key={s} className={`text-[10px] px-1.5 py-0.5 rounded text-${s} fill-current bg-${s}/10`}>
          {sev[s]} {s}
        </span>
      ))}
    </span>
  )
}

/** Line graph: vulnerability counts over time, one line per severity. */
function TrendChart({ scans }: { scans: TargetScan[] }) {
  const completed = scans.filter((s) => s.status === 'completed')
  if (completed.length < 2) return null
  const W = 640, H = 220, PAD = { t: 20, r: 20, b: 40, l: 45 }
  const plotW = W - PAD.l - PAD.r
  const plotH = H - PAD.t - PAD.b

  const maxTotal = Math.max(1, ...completed.map((s) => s.vuln_total))
  const yMax = Math.ceil(maxTotal * 1.15)

  function x(i: number) { return PAD.l + (i / (completed.length - 1)) * plotW }
  function y(v: number) { return PAD.t + plotH - (v / yMax) * plotH }

  function linePath(sev: string) {
    return completed.map((s, i) => {
      const v = s.severity[sev as keyof typeof s.severity]
      return `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(v).toFixed(1)}`
    }).join(' ')
  }

  // Y-axis ticks
  const yTicks = []
  const tickCount = Math.min(5, yMax)
  for (let i = 0; i <= tickCount; i++) {
    yTicks.push(Math.round((yMax / tickCount) * i))
  }

  return (
    <div className="panel p-5">
      <p className="section-title mb-3">Vulnerability trend</p>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ maxHeight: '14rem' }}>
        {/* Grid lines */}
        {yTicks.map((v) => (
          <g key={v}>
            <line x1={PAD.l} y1={y(v)} x2={W - PAD.r} y2={y(v)} className="stroke-current text-border" strokeWidth="0.5" />
            <text x={PAD.l - 6} y={y(v) + 3} textAnchor="end" className="fill-text-dim text-[9px]">{v}</text>
          </g>
        ))}
        {/* X-axis labels */}
        {completed.map((s, i) => (
          <text key={s.job_id} x={x(i)} y={H - PAD.b + 16} textAnchor="middle" className="fill-text-dim text-[9px]">
            {fmtDate(s.completed_at).replace(/, \d{4}/, '')}
          </text>
        ))}
        {/* Severity lines */}
        {SEVS.map((sev) => {
          const total = completed.reduce((a, s) => a + s.severity[sev as keyof typeof s.severity], 0)
          if (total === 0) return null
          return (
            <g key={sev}>
              <path d={linePath(sev)} className={`text-${sev} stroke-current`} fill="none" strokeWidth="1.5" strokeLinejoin="round" />
              {/* Dots */}
              {completed.map((s, i) => {
                const v = s.severity[sev as keyof typeof s.severity]
                return v > 0 ? (
                  <circle key={s.job_id} cx={x(i)} cy={y(v)} r="2.5" className={`text-${sev} fill-current`} stroke="var(--bg-canvas)" strokeWidth="1" />
                ) : null
              })}
            </g>
          )
        })}
      </svg>
      {/* Legend */}
      <div className="flex gap-4 mt-2 justify-center">
        {SEVS.map((sev) => (
          <span key={sev} className="flex items-center gap-1.5 text-[10px] text-text-dim">
            <span className={`w-2.5 h-0.5 rounded text-${sev} bg-current`} />
            {sev}
          </span>
        ))}
      </div>
    </div>
  )
}

/** Before → after: what changed between the two most recent scans. The hook. */
function BeforeAfter({ prev, curr }: { prev: TargetScan; curr: TargetScan }) {
  const prevCves = new Set(prev.cves)
  const currCves = new Set(curr.cves)
  const resolved = prev.cves.filter((c) => !currCves.has(c))
  const added = curr.cves.filter((c) => !prevCves.has(c))
  const prevPorts = new Set(prev.open_ports)
  const currPorts = new Set(curr.open_ports)
  const portsClosed = prev.open_ports.filter((p) => !currPorts.has(p))
  const portsOpened = curr.open_ports.filter((p) => !prevPorts.has(p))
  const critDelta = curr.severity.critical - prev.severity.critical
  const highDelta = curr.severity.high - prev.severity.high

  const improved = resolved.length > 0 || portsClosed.length > 0 || critDelta < 0 || highDelta < 0
  const regressed = added.length > 0 || portsOpened.length > 0 || critDelta > 0 || highDelta > 0

  return (
    <div className="panel p-5 space-y-4">
      <div className="flex items-baseline justify-between">
        <p className="section-title">Progress since last scan</p>
        <span className="text-text-dim text-[11px]">{fmtDate(prev.completed_at)} → {fmtDate(curr.completed_at)}</span>
      </div>

      <div className="grid grid-cols-2 gap-3 text-[12px]">
        <div className="bg-elevated rounded p-3">
          <p className="text-text-dim text-[11px] mb-1">Critical + High</p>
          <p className="text-text-bright">
            {prev.severity.critical + prev.severity.high} → <span className="font-semibold">{curr.severity.critical + curr.severity.high}</span>
            {' '}
            {critDelta + highDelta < 0
              ? <span className="text-low">↓ {Math.abs(critDelta + highDelta)} fixed</span>
              : critDelta + highDelta > 0
                ? <span className="text-critical">↑ {critDelta + highDelta} new</span>
                : <span className="text-text-dim">no change</span>}
          </p>
        </div>
        <div className="bg-elevated rounded p-3">
          <p className="text-text-dim text-[11px] mb-1">Open ports</p>
          <p className="text-text-bright">{prev.open_ports.length} → <span className="font-semibold">{curr.open_ports.length}</span></p>
        </div>
      </div>

      {resolved.length > 0 && (
        <div>
          <p className="text-low text-[11px] mb-1">✓ Resolved since last scan ({resolved.length})</p>
          <div className="flex flex-wrap gap-1.5">
            {resolved.map((c) => <span key={c} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-low/10 text-low line-through">{c}</span>)}
          </div>
        </div>
      )}
      {portsClosed.length > 0 && (
        <p className="text-low text-[11px]">✓ Closed ports: {portsClosed.join(', ')}</p>
      )}
      {added.length > 0 && (
        <div>
          <p className="text-critical text-[11px] mb-1">⚠ Newly appeared ({added.length})</p>
          <div className="flex flex-wrap gap-1.5">
            {added.map((c) => <span key={c} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-critical/10 text-critical">{c}</span>)}
          </div>
        </div>
      )}
      {portsOpened.length > 0 && (
        <p className="text-medium text-[11px]">⚠ Newly opened ports: {portsOpened.join(', ')}</p>
      )}

      {!improved && !regressed && (
        <p className="text-text-dim text-[12px]">No change in findings or ports since the previous scan — posture is stable.</p>
      )}
    </div>
  )
}

export default function TargetTimeline() {
  const { target = '' } = useParams()
  const decoded = decodeURIComponent(target)
  const { data, isLoading } = useTargetHistory(decoded || null)

  const scans = data?.scans ?? []
  const completedScans = scans.filter((s) => s.status === 'completed')
  const running = scans.filter((s) => s.status !== 'completed')
  const latest = completedScans[completedScans.length - 1]
  const prev = completedScans[completedScans.length - 2]

  return (
    <div className="max-w-3xl mx-auto px-6 py-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <Link to="/targets" className="text-accent text-[12px] hover:underline">← All targets</Link>
          <h2 className="font-display font-bold text-lg text-text-bright tracking-wide mt-1 font-mono">{decoded}</h2>
          <p className="text-text-dim text-[12px]">
            {completedScans.length} scan{completedScans.length === 1 ? '' : 's'}
            {running.length > 0 && <> · <span className="text-accent">{running.length} in progress</span></>}
            {completedScans.length > 0 && <> · {fmtDate(completedScans[0].completed_at)} → {fmtDate(latest?.completed_at ?? null)}</>}
          </p>
        </div>
        <Link to="/scans/new" className="btn btn-primary">Re-scan</Link>
      </div>

      {isLoading ? (
        <p className="text-text-dim text-[12px]">Loading history…</p>
      ) : scans.length === 0 ? (
        <p className="text-text-dim text-[12px]">No scans for this target yet.</p>
      ) : (
        <>
          {prev && latest && <BeforeAfter prev={prev} curr={latest} />}

          {running.length > 0 && (
            <div className="panel p-5">
              <p className="section-title mb-3">In progress</p>
              <div className="space-y-1">
                {running.map((s) => (
                  <Link key={s.job_id} to={`/scans/${s.job_id}`}
                    className="flex items-center gap-3 px-2 py-2 rounded hover:bg-elevated text-[12px]">
                    <span className="text-accent w-28 shrink-0">scanning…</span>
                    <span className="w-32"><span className="text-text-dim text-[11px]">{s.progress?.toFixed(0) ?? 0}%</span></span>
                    <span className="ml-auto text-accent text-[10px] animate-pulse">live</span>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {completedScans.length > 1 && <TrendChart scans={completedScans} />}

          {completedScans.length > 0 && (
            <div className="panel p-5">
              <p className="section-title mb-3">Scan history</p>
              <div className="space-y-1">
                {[...completedScans].reverse().map((s) => (
                  <div key={s.job_id} className="flex items-center gap-3 px-2 py-2 rounded text-[12px] group">
                    <Link to={`/scans/${s.job_id}`} className="flex items-center gap-3 flex-1 min-w-0">
                      <span className="text-text-dim w-28 shrink-0">{fmtDate(s.completed_at)}</span>
                      <span className="text-text-dim w-16 shrink-0">{s.open_ports.length} ports</span>
                      <SeverityBadges sev={s.severity} />
                    </Link>
                    {s === latest && <span className="text-accent text-[10px] mr-2">latest</span>}
                    <button
                      onClick={() => downloadExport(s.job_id, 'md', `${decoded}-${s.job_id.slice(0, 8)}.md`)}
                      className="text-text-dim hover:text-text text-[10px] opacity-0 group-hover:opacity-100 transition-opacity"
                      title="Download Markdown report"
                    >Report</button>
                    <button
                      onClick={() => downloadExport(s.job_id, 'json', `${decoded}-${s.job_id.slice(0, 8)}.json`)}
                      className="text-text-dim hover:text-text text-[10px] opacity-0 group-hover:opacity-100 transition-opacity"
                      title="Download JSON export"
                    >JSON</button>
                    <button
                      onClick={() => downloadExport(s.job_id, 'raw', `${decoded}-${s.job_id.slice(0, 8)}_raw.json`)}
                      className="text-text-dim hover:text-text text-[10px] opacity-0 group-hover:opacity-100 transition-opacity"
                      title="Download raw event data"
                    >RAW</button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
