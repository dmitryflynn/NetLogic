import { Link } from 'react-router-dom'
import { useJobs, type JobSummary } from '../api/scan'

interface TargetRow {
  target: string
  scanCount: number
  lastScan: number
  lastVulns: number
  lastPorts: number
}

function fmtDate(ts: number | null): string {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

/** Group completed scans by target → one row per domain, newest activity first. */
function rollup(jobs: JobSummary[]): TargetRow[] {
  const byTarget = new Map<string, JobSummary[]>()
  for (const j of jobs) {
    if (j.status !== 'completed') continue
    const arr = byTarget.get(j.target) ?? []
    arr.push(j)
    byTarget.set(j.target, arr)
  }
  const rows: TargetRow[] = []
  for (const [target, arr] of byTarget) {
    arr.sort((a, b) => (b.completed_at ?? 0) - (a.completed_at ?? 0))
    const last = arr[0]
    rows.push({
      target,
      scanCount: arr.length,
      lastScan: last.completed_at ?? last.created_at,
      lastVulns: last.result_counts.vulnerabilities,
      lastPorts: last.result_counts.ports,
    })
  }
  return rows.sort((a, b) => b.lastScan - a.lastScan)
}

export default function Targets() {
  const { data: jobs = [], isLoading } = useJobs(200)
  const rows = rollup(jobs)

  return (
    <div className="max-w-3xl mx-auto px-6 py-6 space-y-5">
      <div>
        <h2 className="font-display font-bold text-lg text-text-bright tracking-wide">Targets</h2>
        <p className="text-text-dim text-[12px] mt-1">
          Every domain you've scanned, with its history. Open one to see progress over time and
          what changed since the last scan.
        </p>
      </div>

      {isLoading ? (
        <p className="text-text-dim text-[12px]">Loading…</p>
      ) : rows.length === 0 ? (
        <div className="panel p-6 text-center space-y-3">
          <p className="text-text-dim text-[13px]">No completed scans yet.</p>
          <Link to="/scans/new" className="btn btn-primary">Run your first scan</Link>
        </div>
      ) : (
        <div className="panel divide-y divide-border">
          {rows.map((r) => (
            <Link key={r.target} to={`/targets/${encodeURIComponent(r.target)}`}
              className="flex items-center gap-4 px-4 py-3 hover:bg-elevated transition-colors">
              <div className="min-w-0 flex-1">
                <p className="font-mono text-[13px] text-text-bright truncate">{r.target}</p>
                <p className="text-text-dim text-[11px]">
                  {r.scanCount} scan{r.scanCount === 1 ? '' : 's'} · last {fmtDate(r.lastScan)}
                </p>
              </div>
              <div className="text-right shrink-0">
                <p className="text-[12px] text-text-bright">
                  {r.lastVulns} vuln{r.lastVulns === 1 ? '' : 's'}
                </p>
                <p className="text-text-dim text-[11px]">{r.lastPorts} ports</p>
              </div>
              <span className="text-accent text-[12px]">Timeline →</span>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}
