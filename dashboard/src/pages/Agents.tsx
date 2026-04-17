import { useState } from 'react'
import { useAgents, useDeleteAgent, useRegisterAgent } from '../api/scan'
import type { Agent } from '../api/scan'

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

function TokenRow({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <div>
      <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">{label}</p>
      <div className="flex items-center gap-2">
        <code className="text-[11px] text-accent break-all flex-1">{value}</code>
        <button onClick={copy} className="text-[10px] text-text-dim hover:text-text shrink-0 border border-border rounded px-1.5 py-0.5">
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
    </div>
  )
}

function RegisterModal({ onClose }: { onClose: () => void }) {
  const [hostname, setHostname] = useState('')
  const [caps, setCaps]         = useState('scan')
  const [version, setVersion]   = useState('1.0.0')
  const [agentId, setAgentId]   = useState<string | null>(null)
  const reg = useRegisterAgent()

  function submit(e: React.FormEvent) {
    e.preventDefault()
    reg.mutate(
      {
        hostname:     hostname.trim() || window.location.hostname,
        capabilities: caps.split(',').map((s) => s.trim()).filter(Boolean),
        version:      version.trim() || '1.0.0',
        tags:         {},
      },
      { onSuccess: (data) => setAgentId(data.agent_id) },
    )
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div className="panel w-full max-w-md p-6 space-y-4 rounded-xl" onClick={(e) => e.stopPropagation()}>
        {agentId ? (
          <>
            <h3 className="text-text-bright font-bold text-base">Agent Registered</h3>
            <p className="text-[12px] text-text-dim">
              Agent is ready. You can view its token anytime from the agent card.
            </p>
            <button className="btn btn-primary w-full" onClick={onClose}>Done</button>
          </>
        ) : (
          <>
            <h3 className="text-text-bright font-bold text-base">Register Agent</h3>
            <form onSubmit={submit} className="space-y-3">
              <div>
                <label className="text-[11px] text-text-dim uppercase tracking-wide block mb-1">Hostname</label>
                <input
                  className="input w-full"
                  placeholder={window.location.hostname}
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                />
              </div>
              <div>
                <label className="text-[11px] text-text-dim uppercase tracking-wide block mb-1">Capabilities (comma-separated)</label>
                <input
                  className="input w-full"
                  placeholder="scan, tls, osint"
                  value={caps}
                  onChange={(e) => setCaps(e.target.value)}
                />
              </div>
              <div>
                <label className="text-[11px] text-text-dim uppercase tracking-wide block mb-1">Version</label>
                <input
                  className="input w-full"
                  placeholder="1.0.0"
                  value={version}
                  onChange={(e) => setVersion(e.target.value)}
                />
              </div>
              {reg.error && (
                <p className="text-[12px] text-critical">{reg.error.message}</p>
              )}
              <div className="flex gap-2 pt-1">
                <button type="button" className="btn flex-1" onClick={onClose}>Cancel</button>
                <button type="submit" className="btn btn-primary flex-1" disabled={reg.isPending}>
                  {reg.isPending ? 'Registering…' : 'Register'}
                </button>
              </div>
            </form>
          </>
        )}
      </div>
    </div>
  )
}

function AgentTokenSection({ agent }: { agent: Agent }) {
  const [show, setShow] = useState(false)
  if (!agent.token) return null
  return (
    <div className="pt-2 border-t border-border">
      <div className="flex items-center justify-between mb-1">
        <p className="text-[10px] text-text-dim uppercase tracking-wide">Agent Token</p>
        <button onClick={() => setShow((s) => !s)} className="text-[10px] text-text-dim hover:text-text border border-border rounded px-1.5 py-0.5">
          {show ? 'Hide' : 'Reveal'}
        </button>
      </div>
      {show && <TokenRow label="" value={agent.token} />}
    </div>
  )
}

export default function Agents() {
  const { data: agents = [], isLoading } = useAgents()
  const del = useDeleteAgent()
  const [showModal, setShowModal] = useState(false)

  return (
    <div className="px-6 py-6 space-y-4">
      {showModal && <RegisterModal onClose={() => setShowModal(false)} />}

      <div className="flex items-center justify-between">
        <h2 className="font-display font-bold text-lg text-text-bright tracking-wide">
          Remote Agents
        </h2>
        <div className="flex items-center gap-3">
          <span className="text-text-dim text-[11px]">
            {agents.filter((a) => a.status !== 'offline').length} / {agents.length} online
          </span>
          <button className="btn btn-primary text-[12px]" onClick={() => setShowModal(true)}>
            + Register Agent
          </button>
        </div>
      </div>

      {isLoading ? (
        <p className="text-text-dim text-[12px]">Loading…</p>
      ) : agents.length === 0 ? (
        <div className="panel p-8 text-center space-y-3">
          <p className="text-text-dim text-[13px]">No agents registered.</p>
          <button className="btn btn-primary" onClick={() => setShowModal(true)}>
            + Register your first agent
          </button>
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
                      <span className="text-[10px] text-accent">scanning…</span>
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

              <AgentTokenSection agent={a} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
