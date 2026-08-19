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

  const online  = agents.filter((a) => a.status === 'online' || a.status === 'busy').length
  const busy    = agents.filter((a) => a.status === 'busy').length
  const running = jobs.filter((j) => j.status === 'running' || j.status === 'queued').length
  const completed = jobs.filter((j) => j.status === 'completed').length

  return (
    <div className="flex flex-col h-full">
      <div className="px-8 pt-8 pb-6 border-b border-border/60">
        <div className="page-header mb-0 flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="page-title">Scans</h1>
            <p className="page-subtitle">
              Monitor active assessments, review findings, and track scan history across your attack surface.
            </p>
          </div>
          <Link to="/scans/new" className="btn btn-primary shrink-0">
            + New Scan
          </Link>
        </div>
      </div>

      <div className="px-8 py-5 grid grid-cols-2 lg:grid-cols-4 gap-4 shrink-0">
        <Stat label="Active Scans" value={running} accent hint="Queued or running" />
        <Stat label="Completed" value={completed} hint="Finished assessments" />
        <Stat label="Agents Online" value={online} hint={`${busy} busy`} />
        <Stat label="Total Jobs" value={jobs.length} hint="Recent history" />
      </div>

      <div className="flex-1 overflow-y-auto px-8 pb-8">
        {isLoading ? (
          <p className="text-text-dim text-[13px] mt-8 text-center">Loading scans…</p>
        ) : jobs.length === 0 ? (
          <div className="card text-center mt-8 max-w-md mx-auto space-y-4">
            <p className="text-text-bright font-medium">No scans yet</p>
            <p className="text-text-dim text-[13px]">
              Run your first assessment to map open ports, correlate CVEs, and generate an AI executive report.
            </p>
            <Link to="/scans/new" className="btn btn-primary inline-flex">
              Start your first scan
            </Link>
          </div>
        ) : (
          <div className="panel overflow-hidden">
            <table className="w-full text-[13px] border-collapse data-table">
              <thead className="bg-elevated/50">
                <tr>
                  <th className="px-5 pt-4">Target</th>
                  <th className="px-2 pt-4">Status</th>
                  <th className="px-2 pt-4">Progress</th>
                  <th className="px-2 pt-4">Ports</th>
                  <th className="px-2 pt-4">Findings</th>
                  <th className="px-2 pt-4">Started</th>
                  <th className="px-2 pt-4">Elapsed</th>
                  <th className="px-4 pt-4" />
                </tr>
              </thead>
              <tbody>
                {jobs.map((j) => (
                  <tr key={j.job_id}>
                    <td className="px-5">
                      <Link
                        to={`/scans/${j.job_id}`}
                        className="text-accent hover:underline font-medium font-mono text-[12px]"
                      >
                        {j.target}
                      </Link>
                    </td>
                    <td className="px-2">
                      <StatusBadge status={j.status} />
                    </td>
                    <td className="px-2 w-28">
                      <ProgressBar pct={j.progress} status={j.status} />
                    </td>
                    <td className="px-2 text-low font-mono">{j.result_counts.ports}</td>
                    <td className="px-2 text-critical font-mono">{j.result_counts.vulnerabilities}</td>
                    <td className="px-2 text-text-dim text-[12px]">{fmtTime(j.started_at)}</td>
                    <td className="px-2 text-text-dim text-[12px]">{elapsed(j)}</td>
                    <td className="px-4 text-right">
                      {j.status !== 'running' && j.status !== 'queued' && (
                        <button
                          onClick={() => deleteJob.mutate(j.job_id)}
                          className="text-text-dim hover:text-critical text-[11px] transition-colors px-2 py-1 rounded hover:bg-critical/5"
                          title="Delete job"
                        >
                          Delete
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function Stat({ label, value, accent, hint }: { label: string; value: number; accent?: boolean; hint?: string }) {
  return (
    <div className="stat-card">
      <span className="section-title">{label}</span>
      <span className={`block text-2xl font-semibold mt-1 tabular-nums ${accent ? 'text-accent' : 'text-text-bright'}`}>
        {value}
      </span>
      {hint && <span className="text-[11px] text-text-dim mt-1 block">{hint}</span>}
    </div>
  )
}

function ProgressBar({ pct, status }: { pct: number; status: string }) {
  const color =
    status === 'completed' ? 'bg-low' :
    status === 'failed'    ? 'bg-critical' :
    status === 'cancelled' ? 'bg-text-dim' : 'bg-accent'

  return (
    <div className="h-1.5 bg-elevated rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full transition-all duration-500 ${color}`}
        style={{ width: `${pct}%` }}
      />
    </div>
  )
}
