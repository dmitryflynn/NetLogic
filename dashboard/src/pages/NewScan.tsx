import { useState, FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useCreateJob, useAgents, type ScanRequest } from '../api/scan'

const DEFAULT: ScanRequest = {
  target:      '',
  ports:       'quick',
  do_tls:      false,
  do_headers:  false,
  do_stack:    false,
  do_dns:      false,
  do_osint:    false,
  do_probe:    false,
  do_takeover: false,
  do_full:     false,
  cidr:        false,
  timeout:     2,
  threads:     100,
  min_cvss:    4.0,
}

export default function NewScan() {
  const [form, setForm] = useState<ScanRequest>(DEFAULT)
  const [err,  setErr]  = useState('')
  const create          = useCreateJob()
  const { data: agents = [] } = useAgents()
  const nav             = useNavigate()

  function toggle(key: keyof ScanRequest) {
    setForm((prev) => {
      const next = { ...prev, [key]: !prev[key] }
      // do_full overrides individual flags in the UI
      if (key === 'do_full' && !prev.do_full) {
        Object.assign(next, {
          do_tls: true, do_headers: true, do_stack: true,
          do_dns: true, do_osint: true, do_probe: true, do_takeover: true,
        })
      }
      return next
    })
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setErr('')
    try {
      const job = await create.mutateAsync(form)
      nav(`/scans/${job.job_id}`)
    } catch (ex) {
      setErr((ex as Error).message)
    }
  }

  return (
    <div className="max-w-2xl mx-auto px-6 py-6 space-y-6">
      <h2 className="font-display font-bold text-lg text-text-bright tracking-wide">
        New Scan
      </h2>

      <form onSubmit={submit} className="space-y-5">
        {/* Target */}
        <div className="panel p-4 space-y-3">
          <p className="section-title">Target</p>
          <input
            className="input"
            placeholder="hostname, IP, or CIDR (e.g. example.com, 10.0.0.0/24)"
            value={form.target}
            onChange={(e) => setForm({ ...form, target: e.target.value })}
            required
          />
          <label className="flex items-center gap-2 text-[12px] text-text-dim cursor-pointer select-none">
            <input
              type="checkbox"
              checked={form.cidr}
              onChange={() => toggle('cidr')}
              className="accent-accent"
            />
            Treat target as CIDR block (scan every host)
          </label>
        </div>

        {/* Ports */}
        <div className="panel p-4 space-y-3">
          <p className="section-title">Ports</p>
          <div className="flex gap-2">
            {(['quick', 'full'] as const).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setForm({ ...form, ports: p })}
                className={`btn capitalize ${form.ports === p ? 'btn-primary' : ''}`}
              >
                {p}
                <span className="text-[10px] opacity-60 ml-1">
                  {p === 'quick' ? '43 ports' : '58 ports'}
                </span>
              </button>
            ))}
          </div>
          <input
            className="input text-[11px]"
            placeholder="Custom: 21,22,80,443,8080 (leave blank for quick)"
            value={form.ports.startsWith('custom=') ? form.ports.slice(7) : ''}
            onChange={(e) => {
              const v = e.target.value.trim()
              setForm({ ...form, ports: v ? `custom=${v}` : 'quick' })
            }}
          />
        </div>

        {/* Scan modules */}
        <div className="panel p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="section-title">Scan Modules</p>
            <label className="flex items-center gap-2 text-[11px] text-accent cursor-pointer select-none">
              <input
                type="checkbox"
                checked={form.do_full}
                onChange={() => toggle('do_full')}
                className="accent-accent"
              />
              Full scan (all modules)
            </label>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {(
              [
                ['do_tls',      'TLS/SSL Analysis'],
                ['do_headers',  'HTTP Security Headers'],
                ['do_stack',    'Technology Fingerprint'],
                ['do_dns',      'DNS / Email Security'],
                ['do_osint',    'Passive OSINT'],
                ['do_probe',    'Active Service Probes'],
                ['do_takeover', 'Subdomain Takeover'],
              ] as [keyof ScanRequest, string][]
            ).map(([key, label]) => (
              <label
                key={key}
                className="flex items-center gap-2 text-[12px] text-text-dim cursor-pointer select-none hover:text-text"
              >
                <input
                  type="checkbox"
                  checked={!!form[key]}
                  onChange={() => toggle(key)}
                  className="accent-accent"
                />
                {label}
              </label>
            ))}
          </div>
        </div>

        {/* Tuning */}
        <div className="panel p-4 space-y-3">
          <p className="section-title">Tuning</p>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="text-[11px] text-text-dim mb-1 block">Timeout (s)</label>
              <input
                type="number" min={0.5} max={30} step={0.5}
                className="input"
                value={form.timeout}
                onChange={(e) => setForm({ ...form, timeout: parseFloat(e.target.value) })}
              />
            </div>
            <div>
              <label className="text-[11px] text-text-dim mb-1 block">Threads</label>
              <input
                type="number" min={1} max={500}
                className="input"
                value={form.threads}
                onChange={(e) => setForm({ ...form, threads: parseInt(e.target.value) })}
              />
            </div>
            <div>
              <label className="text-[11px] text-text-dim mb-1 block">Min CVSS</label>
              <input
                type="number" min={0} max={10} step={0.1}
                className="input"
                value={form.min_cvss}
                onChange={(e) => setForm({ ...form, min_cvss: parseFloat(e.target.value) })}
              />
            </div>
          </div>
        </div>

        {/* Agent routing */}
        <div className="panel p-4 space-y-3">
          <p className="section-title">Agent</p>
          <select
            className="input"
            value={form.agent_id ?? ''}
            onChange={(e) => setForm({ ...form, agent_id: e.target.value || undefined })}
          >
            <option value="">Auto-assign to any available agent</option>
            {agents
              .filter((a) => a.status !== 'offline')
              .map((a) => (
                <option key={a.agent_id} value={a.agent_id}>
                  {a.hostname} ({a.status})
                </option>
              ))}
          </select>
          {agents.filter((a) => a.status !== 'offline').length === 0 && (
            <p className="text-[11px] text-high">
              No agents online — job will queue until one registers and heartbeats in.
            </p>
          )}
        </div>

        {err && (
          <p className="text-critical text-[11px] bg-critical/10 border border-critical/30 rounded px-3 py-2">
            {err}
          </p>
        )}

        <div className="flex gap-3">
          <button
            type="submit"
            disabled={create.isPending || !form.target.trim()}
            className="btn btn-primary px-8 disabled:opacity-40"
          >
            {create.isPending ? 'Starting…' : 'Start Scan'}
          </button>
          <button
            type="button"
            onClick={() => nav(-1)}
            className="btn"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  )
}
