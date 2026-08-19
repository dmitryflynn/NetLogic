import { Link } from 'react-router-dom'
import { useJobs, type JobSummary } from '../api/scan'

interface TargetRow {
  target: string
  scanCount: number
  lastScan: number
  lastVulns: number
  lastPorts: number
  lastStatus: string
}

function fmtDate(ts: number | null): string {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

/** Group scans by target → one row per domain, newest activity first. */
function rollup(jobs: JobSummary[]): TargetRow[] {
  const byTarget = new Map<string, JobSummary[]>()
  for (const j of jobs) {
    const arr = byTarget.get(j.target) ?? []
    arr.push(j)
    byTarget.set(j.target, arr)
  }
  const rows: TargetRow[] = []
  for (const [target, arr] of byTarget) {
    arr.sort((a, b) => (b.completed_at ?? b.started_at ?? b.created_at) - (a.completed_at ?? a.started_at ?? a.created_at))
    const last = arr[0]
    rows.push({
      target,
      scanCount: arr.length,
      lastScan: last.completed_at ?? last.started_at ?? last.created_at,
      lastVulns: last.result_counts.vulnerabilities,
      lastPorts: last.result_counts.ports,
      lastStatus: last.status,
    })
  }
  return rows.sort((a, b) => b.lastScan - a.lastScan)
}

export default function Targets() {
  const { data: jobs = [], isLoading } = useJobs(200)
  const rows = rollup(jobs)

  return (
    <div className="max-w-4xl mx-auto px-8 py-8 space-y-6">
      <div className="page-header">
        <h1 className="page-title">Targets</h1>
        <p className="page-subtitle">
          Every asset you have assessed, with scan history and posture trends over time.
        </p>
      </div>

      {isLoading ? (
        <p className="text-text-dim text-[13px]">Loading targets…</p>
      ) : rows.length === 0 ? (
        <div className="card text-center space-y-4">
          <p className="text-text-bright font-medium">No targets yet</p>
          <p className="text-text-dim text-[13px]">Complete a scan to start building your target inventory.</p>
          <Link to="/scans/new" className="btn btn-primary inline-flex">Run your first scan</Link>
        </div>
      ) : (
        <div className="panel divide-y divide-border overflow-hidden">
          {rows.map((r) => (
            <Link
              key={r.target}
              to={`/targets/${encodeURIComponent(r.target)}`}
              className="flex items-center gap-4 px-5 py-4 hover:bg-elevated/50 transition-colors"
            >
              <div className="min-w-0 flex-1">
                <p className="font-mono text-[13px] text-text-bright truncate">{r.target}</p>
                <p className="text-text-dim text-[11px] mt-0.5">
                  {r.scanCount} scan{r.scanCount === 1 ? '' : 's'} · last {fmtDate(r.lastScan)}
                  {r.lastStatus !== 'completed' && (
                    <span className="ml-2 text-accent capitalize">{r.lastStatus}</span>
                  )}
                </p>
              </div>
              <div className="text-right shrink-0">
                <p className="text-[13px] text-text-bright font-mono tabular-nums">
                  {r.lastVulns} finding{r.lastVulns === 1 ? '' : 's'}
                </p>
                <p className="text-text-dim text-[11px]">{r.lastPorts} ports</p>
              </div>
              <span className="text-accent text-[12px] shrink-0">Timeline →</span>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
