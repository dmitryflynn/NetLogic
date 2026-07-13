import { useState, FormEvent } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useCreateJob, useAgents, useAiSettings, type ScanRequest } from '../api/scan'

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
  do_ai:       false,
  ai_provider: '',
  ai_key:      '',
  ai_model:    '',
  ai_base_url: '',
  do_reason:      false,
  do_since_last:  false,
  do_multi_host:  false,
  do_active_validate: false,
  do_ai_driven:   false,
  do_ai_agent:    false,
  agent_depth:    false,
  allow_crash_probes: false,
  allow_freeform_proof: false,
  allow_exploit_requests: false,
  agent_max_steps: 12,
  agent_max_requests: 40,
  ssh_user:    '',
  ssh_key:     '',
  ssh_pass:    '',
  ssh_port:    22,
}

export default function NewScan() {
  const [form, setForm] = useState<ScanRequest>(DEFAULT)
  const [phaseTest, setPhaseTest] = useState(false)
  const [err,  setErr]  = useState('')
  const create          = useCreateJob()
  const { data: agents = [] } = useAgents()
  const { data: ai }    = useAiSettings()
  const nav             = useNavigate()

  function toggle(key: keyof ScanRequest) {
    setForm((prev) => {
      const next = { ...prev, [key]: !prev[key] }
      // do_full overrides individual flags in the UI
      if (key === 'do_full') {
        if (prev.do_full) {
          // Unchecking full — clear all sub-options
          Object.assign(next, {
            do_tls: false, do_headers: false, do_stack: false,
            do_dns: false, do_osint: false, do_probe: false, do_takeover: false,
          })
        } else {
          // Checking full — enable all sub-options
          Object.assign(next, {
            do_tls: true, do_headers: true, do_stack: true,
            do_dns: true, do_osint: true, do_probe: true, do_takeover: true,
          })
        }
      } else {
        // Unchecking a sub-option while full is on — clear full
        if (prev.do_full && !next[key]) {
          next.do_full = false
        }
      }
      return next
    })
  }

  function togglePhaseTest() {
    const on = !phaseTest
    setPhaseTest(on)
    setForm((prev) => ({
      ...prev,
      do_reason: on, do_since_last: on, do_multi_host: on,
      do_active_validate: on, do_ai_driven: on, do_ai_agent: on, agent_depth: on,
    }))
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setErr('')
    // Validate custom port list
    if (form.ports.startsWith('custom=')) {
      const raw = form.ports.slice(7)
      const parts = raw.split(',').map((s) => s.trim()).filter(Boolean)
      if (parts.length === 0) {
        setErr('Custom port list is empty.')
        return
      }
      for (const p of parts) {
        const n = parseInt(p, 10)
        if (isNaN(n) || n < 1 || n > 65535) {
          setErr(`Invalid port "${p}" — must be 1–65535.`)
          return
        }
      }
    }
    // AI provider/key/model come from server-side Settings (configure once),
    // not per-scan — the scan just toggles do_ai on.
    const payload: ScanRequest = {
      ...form,
      target: form.target.trim(),
    }
    try {
      const job = await create.mutateAsync(payload)
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

      {err && (
        <div className="flex items-start justify-between gap-3 text-critical text-[12px] bg-critical/10 border border-critical/30 rounded px-3 py-2">
          <span>{err}</span>
          <button
            type="button"
            onClick={() => setErr('')}
            className="text-critical/70 hover:text-critical shrink-0 leading-none text-base"
          >
            ✕
          </button>
        </div>
      )}

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

        {/* AI Analysis + Authenticated scanning */}
        <div className="panel p-4 space-y-3">
          <p className="section-title">AI &amp; Authenticated Scan</p>
          <label className="flex items-center gap-2 text-[12px] text-text-dim cursor-pointer select-none hover:text-text">
            <input type="checkbox" checked={!!form.do_ai} onChange={() => toggle('do_ai')} className="accent-accent" />
            AI analysis &amp; attack-chain reasoning
            <span className="text-[10px] text-text-dim/70">(auto-enables deep detection)</span>
          </label>
          {form.do_ai && (
            <div className="text-[11px] pt-1">
              {ai?.key_set ? (
                <span className="text-text-dim">
                  Using <span className="text-text">{ai.provider}{ai.model ? ` · ${ai.model}` : ''}</span> from{' '}
                  <Link to="/settings" className="text-accent hover:underline">Settings</Link>.
                </span>
              ) : (
                <span className="text-medium">
                  No AI key configured — set one in{' '}
                  <Link to="/settings" className="text-accent hover:underline">Settings</Link>,
                  or AI analysis will be skipped.
                </span>
              )}
            </div>
          )}
          <div className="grid grid-cols-2 gap-2 pt-1">
            <input className="input text-[11px]" placeholder="SSH user (authenticated scan)"
              value={form.ssh_user ?? ''} onChange={(e) => setForm({ ...form, ssh_user: e.target.value })} />
            <input className="input text-[11px]" placeholder="SSH port" type="number"
              value={form.ssh_port ?? 22} onChange={(e) => setForm({ ...form, ssh_port: parseInt(e.target.value) || 22 })} />
            <input className="input text-[11px]" placeholder="SSH private key path"
              value={form.ssh_key ?? ''} onChange={(e) => setForm({ ...form, ssh_key: e.target.value })} />
            <input className="input text-[11px]" placeholder="SSH password (needs sshpass)" type="password"
              value={form.ssh_pass ?? ''} onChange={(e) => setForm({ ...form, ssh_pass: e.target.value })} />
          </div>
          <p className="text-[10px] text-text-dim/70">
            Authenticated scanning reads real installed package versions (patch-level ground truth). Key auth recommended.
          </p>
        </div>

        {/* AI Deep Verification — the demo-facing one-click for the tool-driven agent */}
        <div className="panel p-4 space-y-3 border-accent/40">
          <label className="flex items-start gap-3 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={!!form.agent_depth && !!form.do_ai_agent}
              onChange={() => {
                const on = !(form.agent_depth && form.do_ai_agent)
                setForm((prev) => ({
                  ...prev,
                  do_ai_agent: on,
                  agent_depth: on,
                  // turning it off should also disarm opt-in intrusive tools
                  allow_crash_probes: on ? prev.allow_crash_probes : false,
                  allow_freeform_proof: on ? prev.allow_freeform_proof : false,
                  allow_exploit_requests: on ? prev.allow_exploit_requests : false,
                }))
              }}
              className="accent-accent mt-0.5"
            />
            <span>
              <span className="section-title text-accent">AI Deep Verification</span>
              <span className="block text-[11px] text-text-dim mt-1 leading-relaxed">
                Baseline sensors run first, then the AI drives read-only tools (HTTP/TLS/DNS probes,
                dir enum, tech confirm, timing) to verify CVE leads and build attack chains — instead of
                leaving them as unverified banner matches. Raises budgets (~24 steps / 80 requests) and
                blocks early stop until enough high-value checks run.
              </span>
            </span>
          </label>
          {form.agent_depth && form.do_ai_agent && (
            <>
            <label className="flex items-start gap-3 cursor-pointer select-none pl-7 pt-1 border-t border-border/40">
              <input
                type="checkbox"
                checked={!!form.allow_freeform_proof}
                onChange={() => toggle('allow_freeform_proof')}
                className="accent-accent mt-0.5"
              />
              <span>
                <span className="text-[12px] font-medium text-accent">
                  Freeform proof payloads (Tier C)
                </span>
                <span className="block text-[10px] text-text-dim mt-0.5 leading-relaxed">
                  Lets the agent craft custom GET/query/header proofs (and limited POST on
                  search/login/graphql-like paths) to concretely expose vulns.
                  <span className="text-low"> Engine blocks destructive patterns and never
                  allows PUT/PATCH/DELETE — designed not to wipe or mutate user data.</span>
                </span>
              </span>
            </label>
            <label className="flex items-start gap-3 cursor-pointer select-none pl-7 pt-1 border-t border-border/40">
              <input
                type="checkbox"
                checked={!!form.allow_crash_probes}
                onChange={() => toggle('allow_crash_probes')}
                className="accent-high mt-0.5"
              />
              <span>
                <span className="text-[12px] font-medium text-high">
                  Confirm crash-class CVEs (http.sys / MS15-034)
                </span>
                <span className="block text-[10px] text-text-dim mt-0.5 leading-relaxed">
                  Sends curated crash/DoS probes so the agent can actively CONFIRM CVEs a banner alone
                  can't (e.g. CVE-2021-31166). <span className="text-high">May crash or blue-screen the
                  host — authorized lab targets you own only.</span>
                </span>
              </span>
            </label>
            </>
          )}
        </div>

        {/* Phase Test */}
        <div className="panel p-4 space-y-3">
          <div className="flex items-center justify-between">
            <p className="section-title">Phase Test</p>
            <label className="flex items-center gap-2 text-[11px] text-accent cursor-pointer select-none">
              <input
                type="checkbox"
                checked={phaseTest}
                onChange={togglePhaseTest}
                className="accent-accent"
              />
              Phase Test (all phases)
            </label>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {(
              [
                ['do_reason',     'Adaptive Reasoning Loop'],
                ['do_since_last', 'Change Detection Since Last Scan'],
                ['do_multi_host', 'Multi-Host World Modeling'],
                ['do_active_validate', 'Active Validation (safe, authorized)'],
                ['do_ai_driven', 'AI-Driven Adjudication (AI resolves unverifiable CVEs)'],
                ['do_ai_agent', 'AI Investigation Agent (AI chooses tools after baseline)'],
                ['agent_depth', 'Agent depth mode (CVE leads, chains, no early stop)'],
                ['allow_crash_probes', 'Allow crash/DoS probes (MAY disrupt target)'],
                ['allow_freeform_proof', 'Freeform proof payloads (Tier C, non-destructive)'],
                ['allow_exploit_requests', 'Freeform EXPLOIT requests (Tier E — any method; AUTHORIZED targets only)'],
              ] as [keyof ScanRequest, string][]
            ).map(([key, label]) => (
              <label
                key={key}
                className="flex items-center gap-2 text-[12px] text-text-dim cursor-pointer select-none hover:text-text"
              >
                <input
                  type="checkbox"
                  checked={!!form[key]}
                  onChange={() => {
                    if (key === 'agent_depth' && !form.agent_depth) {
                      // Depth implies agent on
                      setForm((prev) => ({ ...prev, agent_depth: true, do_ai_agent: true }))
                      return
                    }
                    toggle(key)
                  }}
                  className="accent-accent"
                />
                {label}
              </label>
            ))}
          </div>
          <p className="text-[10px] text-text-dim/70">
            Reasoning loop enables deterministic observe→reason→act analysis. Change detection diffs against the prior scan snapshot.
            Multi-host modeling discovers in-scope neighbors and reasons over each host individually.
            Active validation confirms hypotheses with non-destructive, scope-gated, audited checks (safe_active only; requires reasoning). Authorized targets only.
            <span className="block mt-1 text-accent/80">
              AI Investigation Agent: baseline first, then AI picks tools. Depth mode raises budgets (~24 steps / 80 requests),
              prioritizes CVE leads & attack chains, and blocks early stop until enough high-value checks run.
              Crash probes (http.sys etc.) stay off unless allowed — they can blue-screen a host.
              Freeform proof (Tier C) stays off unless allowed — still non-destructive (no wipe/delete).
            </span>
          </p>
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
              .filter((a) => a.status === 'online' || a.status === 'busy')
              .map((a) => (
                <option key={a.agent_id} value={a.agent_id}>
                  {a.hostname} ({a.status})
                </option>
              ))}
          </select>
          {agents.filter((a) => a.status === 'online' || a.status === 'busy').length === 0 && (
            <p className="text-[11px] text-high">
              No agents online — job will queue until one registers and heartbeats in.
            </p>
          )}
        </div>

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
