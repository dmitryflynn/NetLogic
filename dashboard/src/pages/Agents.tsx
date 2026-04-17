import { useAgents, useDeleteAgent } from '../api/scan'

function fmtDate(ts: number | null) {
  if (!ts) return 'Never'
  const ago = Math.round((Date.now() / 1000) - ts)
  if (ago < 60)   return `${ago}s ago`
  if (ago < 3600) return `${Math.floor(ago / 60)}m ago`
  return new Date(ts * 1000).toLocaleTimeString()
}

const STATUS_COLORS = {
  online:  'text-low border-low/30 bg-low/10',
  busy:    'text-accent border-accent/30 bg-accent/10',
  offline: 'text-text-dim border-border bg-elevated',
}

export default function Agents() {
  const { data: agents = [], isLoading } = useAgents()
  const del = useDeleteAgent()

  return (
    <div className="px-6 py-6 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="font-display font-bold text-lg text-text-bright tracking-wide">
          Remote Agents
        </h2>
        <span className="text-text-dim text-[11px]">
          {agents.filter((a) => a.status !== 'offline').length} / {agents.length} online
        </span>
      </div>

      {isLoading ? (
        <p className="text-text-dim text-[12px]">Loading…</p>
      ) : agents.length === 0 ? (
        <div className="panel p-8 text-center space-y-2">
          <p className="text-text-dim text-[13px]">No agents registered.</p>
          <p className="text-text-dim text-[11px]">
            Register an agent by calling <code className="text-accent">POST /agents/register</code>.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {agents.map((a) => (
            <div key={a.agent_id} className="panel p-4 space-y-3">
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="text-text-bright font-medium">{a.hostname}</span>
                    <span
                      className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide ${STATUS_COLORS[a.status]}`}
                    >
                      {a.status}
                    </span>
                    {a.current_job_id && (
                      <span className="text-[10px] text-accent">
                        scanning…
                      </span>
                    )}
                  </div>
                  <p className="text-text-dim text-[11px]">
                    v{a.version} · {a.agent_id.slice(0, 8)}
                  </p>
                </div>
                <button
                  onClick={() => del.mutate(a.agent_id)}
                  className="btn btn-danger text-[11px] shrink-0"
                  disabled={del.isPending}
                >
                  Deregister
                </button>
              </div>

              <div className="grid grid-cols-3 gap-4 text-[11px]">
                <div>
                  <p className="text-text-dim mb-0.5">Last heartbeat</p>
                  <p className={a.status === 'offline' ? 'text-critical' : 'text-text'}>
                    {fmtDate(a.last_heartbeat)}
                  </p>
                </div>
                <div>
                  <p className="text-text-dim mb-0.5">Capabilities</p>
                  <p className="text-text">{a.capabilities.join(', ') || '—'}</p>
                </div>
                <div>
                  <p className="text-text-dim mb-0.5">Current job</p>
                  <p className="text-accent font-mono">
                    {a.current_job_id ? a.current_job_id.slice(0, 8) + '…' : '—'}
                  </p>
                </div>
              </div>

              {Object.keys(a.tags).length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(a.tags).map(([k, v]) => (
                    <span
                      key={k}
                      className="text-[10px] bg-elevated border border-border rounded px-1.5 py-0.5 text-text-dim"
                    >
                      {k}={v}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
