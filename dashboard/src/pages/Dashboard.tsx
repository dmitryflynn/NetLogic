import { Link } from 'react-router-dom'
import { useJobs, useDeleteJob, useAgents } from '../api/scan'
import StatusBadge from '../components/StatusBadge'

function fmtTime(ts: number | null): string {
  if (!ts) return '—'
  return new Date(ts * 1000).toLocaleString()
}

function elapsed(job: { started_at: number | null; completed_at: number | null }): string {
  if (!job.started_at) return '—'
  const end = job.completed_at ?? Date.now() / 1000
  const s = Math.round(end - job.started_at)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${s % 60}s`
}

export default function Dashboard() {
  const { data: jobs = [], isLoading } = useJobs(50)
  const { data: agents = [] }          = useAgents()
  const deleteJob                       = useDeleteJob()

  const online = agents.filter((a) => a.status !== 'offline').length
  const busy   = agents.filter((a) => a.status === 'busy').length
  const running = jobs.filter((j) => j.status === 'running' || j.status === 'queued').length

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Stat bar */}
      <div className="flex gap-4 px-6 py-3 border-b border-border bg-panel shrink-0">
        <Stat label="Active Scans"   value={running} accent />
        <Stat label="Agents Online"  value={online} />
        <Stat label="Agents Busy"    value={busy} />
        <Stat label="Total Jobs"     value={jobs.length} />
        <div className="ml-auto">
          <Link to="/scans/new" className="btn btn-primary">
            + New Scan
          </Link>
        </div>
      </div>

      {/* Jobs table */}
      <div className="flex-1 overflow-y-auto px-6 py-4">
        {isLoading ? (
          <p className="text-text-dim text-[12px] mt-8 text-center">Loading…</p>
        ) : jobs.length === 0 ? (
          <div className="text-center mt-16 space-y-3">
            <p className="text-text-dim">No scans yet.</p>
            <Link to="/scans/new" className="btn btn-primary">
              Start your first scan
            </Link>
          </div>
        ) : (
          <table className="w-full text-[12px] border-collapse">
            <thead>
              <tr className="text-left text-text-dim border-b border-border">
                <th className="pb-2 font-medium tracking-wide">Target</th>
                <th className="pb-2 font-medium">Status</th>
                <th className="pb-2 font-medium">Progress</th>
                <th className="pb-2 font-medium">Ports</th>
                <th className="pb-2 font-medium">Vulns</th>
                <th className="pb-2 font-medium">Started</th>
                <th className="pb-2 font-medium">Elapsed</th>
                <th className="pb-2" />
              </tr>
            </thead>
            <tbody>
              {jobs.map((j) => (
                <tr
                  key={j.job_id}
                  className="border-b border-border/50 hover:bg-elevated/50 transition-colors"
                >
                  <td className="py-2 pr-4">
                    <Link
                      to={`/scans/${j.job_id}`}
                      className="text-accent hover:underline font-medium"
                    >
                      {j.target}
                    </Link>
                  </td>
                  <td className="py-2 pr-4">
                    <StatusBadge status={j.status} />
                  </td>
                  <td className="py-2 pr-4 w-24">
                    <ProgressBar pct={j.progress} status={j.status} />
                  </td>
                  <td className="py-2 pr-4 text-low">{j.result_counts.ports}</td>
                  <td className="py-2 pr-4 text-critical">{j.result_counts.vulnerabilities}</td>
                  <td className="py-2 pr-4 text-text-dim">{fmtTime(j.started_at)}</td>
                  <td className="py-2 pr-4 text-text-dim">{elapsed(j)}</td>
                  <td className="py-2">
                    {j.status !== 'running' && j.status !== 'queued' && (
                      <button
                        onClick={() => deleteJob.mutate(j.job_id)}
                        className="text-text-dim hover:text-critical text-[11px] transition-colors"
                        title="Delete job"
                      >
                        ✕
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function Stat({ label, value, accent }: { label: string; value: number; accent?: boolean }) {
  return (
    <div className="flex flex-col">
      <span className="text-[10px] text-text-dim tracking-wider uppercase">{label}</span>
      <span className={`text-xl font-bold font-display ${accent ? 'text-accent' : 'text-text-bright'}`}>
        {value}
      </span>
    </div>
  )
}

function ProgressBar({ pct, status }: { pct: number; status: string }) {
  const color =
    status === 'completed' ? 'bg-low' :
    status === 'failed'    ? 'bg-critical' :
    status === 'cancelled' ? 'bg-text-dim' : 'bg-accent'

  return (
    <div className="h-1 bg-elevated rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full transition-all duration-500 ${color}`}
        style={{ width: `${pct}%` }}
      />
    </div>
  )
}
