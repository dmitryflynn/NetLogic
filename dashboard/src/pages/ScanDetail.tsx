import { useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useJob, useCancelJob, useStreamScan, extractSections, exploreBeyond, downloadExport, type PortEvent, type VulnEvent } from '../api/scan'
import StatusBadge from '../components/StatusBadge'
import PortTable from '../components/PortTable'
import ScanFeed from '../components/ScanFeed'
import ScanSections from '../components/ScanSections'

function fmtDate(ts: number | null) {
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const nav    = useNavigate()

  if (!id) {
    return <p className="text-critical p-8 text-center">Invalid scan ID.</p>
  }

  const { data: job, isLoading } = useJob(id)
  const cancel = useCancelJob()

  // SSE stream while job is running/queued. After finish, fall back to persisted job.events
  // so the event log remains accessible (not only during the live window).
  const live = (job?.status === 'running' || job?.status === 'queued')
  const { events: streamEvents, ports, progress, streaming } = useStreamScan(live ? id : null)

  // Prefer the richest event list: live SSE while connected; otherwise stored history.
  // If the stream ended but the job poll still has fewer events, keep stream buffer until
  // the job payload catches up (avoids a flash of empty log at completion).
  const activeEvents = useMemo(() => {
    const stored = job?.events ?? []
    if (live && streamEvents.length > 0) return streamEvents
    if (!live && streamEvents.length > stored.length) return streamEvents
    if (stored.length > 0) return stored
    return streamEvents
  }, [live, streamEvents, job?.events])

  // The scan engine emits vulns nested as {port, service, cves:[{id, cvss_score,...}]};
  // flatten to the VulnEvent shape the UI expects. Used for both live and stored.
  const displayVulns = useMemo(() =>
    activeEvents.filter((e) => e.type === 'vuln').flatMap((e) => {
      const d = e.data as Record<string, unknown> | undefined
      if (!d) return []
      if (Array.isArray(d.cves) && d.cves.length > 0) {
        return (d.cves as Record<string, unknown>[]).map((c) => ({
          cve_id:      c.id as string,
          cvss:        c.cvss_score as number,
          severity:    c.severity as string,
          description: (c.description ?? '') as string,
          port:        d.port as number,
          service:     (d.service ?? '') as string,
          exploitable: (c.exploit_available ?? false) as boolean,
          exploit_ref: (Array.isArray(c.references) ? c.references[0] : undefined) as string | undefined,
          kev:         (c.kev ?? false) as boolean,
          epss:        (c.epss ?? 0) as number,
        } satisfies VulnEvent))
      }
      return [d as unknown as VulnEvent]
    }),
    [activeEvents],
  )

  const displayPorts = useMemo(() => {
    if (live) return ports
    return activeEvents.filter((e) => e.type === 'port').map((e) => e.data as PortEvent)
  }, [live, ports, activeEvents])

  const displayPct   = live ? (progress?.percent ?? job?.progress ?? 0) : (job?.progress ?? 0)
  // Deep-scan sections (topology, exploitability, web fp, AI, TLS, changes).
  const sections     = useMemo(() => extractSections(activeEvents), [activeEvents])

  // Findings count from operator-facing surfaces (AI + triage + agent)
  const findingsTotal = useMemo(() => {
    const beyondCves = (sections.ai?.beyond_cves as string[] | undefined)?.length ?? 0
    const triageAttn = sections.triage?.attention?.length ?? 0
    const agentConf = sections.aiAgent?.confirmed ?? 0
    return beyondCves + triageAttn + agentConf
  }, [sections])

  // Inline explore for Beyond CVEs
  const [exploring, setExploring] = useState<string | null>(null)
  const [exploreMd, setExploreMd] = useState<Record<string, string>>({})

  // Tabs: Summary (Executive | Technical) vs Data. Live scans open on Data (the live stream).
  const [tab, setTab] = useState<'summary' | 'data'>(live ? 'data' : 'summary')
  const [subTab, setSubTab] = useState<'executive' | 'technical'>('executive')
  async function onExplore(finding: string) {
    if (!id) return
    if (exploreMd[finding]) return  // already loaded
    setExploring(finding)
    try {
      const res = await exploreBeyond(id, finding)
      setExploreMd((prev) => ({ ...prev, [finding]: res.markdown || res.error || 'No elaboration returned.' }))
    } catch {
      setExploreMd((prev) => ({ ...prev, [finding]: '_Failed to retrieve elaboration._' }))
    } finally {
      setExploring(null)
    }
  }

  if (isLoading) {
    return <p className="text-text-dim p-8 text-center">Loading…</p>
  }
  if (!job) {
    return <p className="text-critical p-8 text-center">Job not found.</p>
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="shrink-0 px-6 py-3 border-b border-border bg-panel flex items-center gap-4">
        <button onClick={() => nav('/')} className="text-text-dim hover:text-text text-[12px]">
          ← Back
        </button>
        <span className="font-display font-bold text-text-bright tracking-wide">{job.target}</span>
        <StatusBadge status={job.status} />
        {streaming && (
          <span className="text-accent text-[11px] animate-pulse">● Live</span>
        )}
        <div className="ml-auto flex gap-2">
          {job.status !== 'queued' && (
            <>
              <button
                onClick={() => downloadExport(job.job_id, 'json', `${job.target}-${job.job_id.slice(0, 8)}.json`)}
                className="btn text-[11px]"
                title="Download JSON export"
              >
                JSON
              </button>
              <button
                onClick={() => downloadExport(job.job_id, 'md', `${job.target}-${job.job_id.slice(0, 8)}.md`)}
                className="btn text-[11px]"
                title="Download Markdown report"
              >
                Report
              </button>
              <button
                onClick={() => downloadExport(job.job_id, 'raw', `${job.target}-${job.job_id.slice(0, 8)}_raw.json`)}
                className="btn text-[11px]"
                title="Download raw event data"
              >
                Export RAW
              </button>
            </>
          )}
          {(job.status === 'running' || job.status === 'queued') && (
            <button
              onClick={() => cancel.mutate(job.job_id)}
              className="btn btn-danger"
              disabled={cancel.isPending}
            >
              Cancel
            </button>
          )}
        </div>
      </div>

      {/* Tab bar — Summary vs Data */}
      {job.status !== 'queued' && (
        <div className="shrink-0 px-6 border-b border-border bg-panel flex items-center gap-1">
          <TabBtn active={tab === 'summary'} onClick={() => setTab('summary')}>Summary</TabBtn>
          <TabBtn active={tab === 'data'} onClick={() => setTab('data')}>Data</TabBtn>
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">
        {/* Main content */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6">
          {/* Progress bar */}
          {(job.status === 'running' || job.status === 'queued') && (
            <div>
              <div className="flex justify-between text-[11px] text-text-dim mb-1">
                <span>Scanning…</span>
                <span>{Math.round(displayPct)}%</span>
              </div>
              <div className="h-1.5 bg-elevated rounded-full overflow-hidden">
                <div
                  className="h-full bg-accent rounded-full transition-all duration-300"
                  style={{ width: `${displayPct}%` }}
                />
              </div>
            </div>
          )}

          {/* Error */}
          {job.error && (
            <div className="bg-critical/10 border border-critical/30 rounded-lg px-4 py-3 text-critical text-[12px]">
              {job.error}
            </div>
          )}

          {/* ── Tab content ── */}
          {tab === 'summary' ? (
            <>
              {/* Executive vs Technical sub-tabs */}
              <div className="flex items-center gap-1 border-b border-border/60">
                <SubTabBtn active={subTab === 'executive'} onClick={() => setSubTab('executive')}>
                  Executive Summary
                </SubTabBtn>
                <SubTabBtn active={subTab === 'technical'} onClick={() => setSubTab('technical')}>
                  Technical Summary
                </SubTabBtn>
              </div>
              <ScanSections s={sections} view={subTab} onExplore={onExplore} exploreMd={exploreMd} exploring={exploring} />
            </>
          ) : (
            <>
              {/* Open Ports — supporting evidence. Catalog version-matches are not findings. */}
              {displayPorts.length > 0 && (
                <section>
                  <p className="section-title mb-3">Open Ports ({displayPorts.length})</p>
                  <PortTable ports={displayPorts} />
                </section>
              )}
              <ScanSections s={sections} view="data" onExplore={onExplore} exploreMd={exploreMd} exploring={exploring} />

              {/* Event stream — live while scanning; persists after completion from job.events */}
              {activeEvents.length > 0 && (
                <ScanFeed
                  events={activeEvents}
                  live={!!live && streaming}
                  defaultOpen={live || job.status === 'failed'}
                />
              )}

              {displayPorts.length === 0 && displayVulns.length === 0 &&
               !live && job.status === 'completed' && activeEvents.length === 0 && (
                <p className="text-text-dim text-[12px] text-center mt-8">
                  No open ports or vulnerabilities found.
                </p>
              )}
            </>
          )}
        </div>

        {/* Sidebar */}
        <aside className="w-56 shrink-0 border-l border-border bg-panel overflow-y-auto">
          <div className="p-4 space-y-4">
            <div>
              <p className="section-title mb-2">Scan Info</p>
              <dl className="space-y-1.5 text-[11px]">
                <Row k="Job ID"    v={job.job_id.slice(0, 8) + '…'} />
                <Row k="Status"    v={<StatusBadge status={job.status} />} />
                <Row k="Progress"  v={`${Math.round(job.progress)}%`} />
                <Row k="Created"   v={fmtDate(job.created_at)} />
                <Row k="Started"   v={fmtDate(job.started_at)} />
                <Row k="Finished"  v={fmtDate(job.completed_at)} />
              </dl>
            </div>

            <div>
              <p className="section-title mb-2">Config</p>
              <dl className="space-y-1.5 text-[11px]">
                <Row k="Ports"    v={job.config.ports} />
                <Row k="Timeout"  v={`${job.config.timeout}s`} />
                <Row k="Threads"  v={job.config.threads} />
                <Row k="Min CVSS" v={job.config.min_cvss} />
                {job.config.do_full    && <Flag label="Full scan" />}
                {job.config.do_tls     && <Flag label="TLS" />}
                {job.config.do_headers && <Flag label="Headers" />}
                {job.config.do_dns     && <Flag label="DNS" />}
                {job.config.do_stack   && <Flag label="Stack" />}
                {job.config.do_probe   && <Flag label="Probe" />}
                {job.config.do_osint   && <Flag label="OSINT" />}
                {job.config.do_ai_agent && <Flag label="AI Agent" />}
                {job.config.agent_depth && <Flag label="Depth" />}
                {job.config.allow_crash_probes && <Flag label="Crash probes" />}
                {job.config.allow_freeform_proof && <Flag label="Freeform proof" />}
                {job.config.allow_exploit_requests && <Flag label="Exploit requests" />}
              </dl>
            </div>

            <div>
              <p className="section-title mb-2">Results</p>
              <dl className="space-y-1.5 text-[11px]">
                {sections.architecture?.stack_kind && (
                  <Row k="Stack" v={<span className="text-text-bright capitalize">{sections.architecture.stack_kind.replace(/-/g, ' ')}</span>} />
                )}
                {(sections.architecture?.components?.length ?? 0) > 0 && (
                  <Row k="Components" v={<span className="text-text-bright">{sections.architecture!.components!.length}</span>} />
                )}
                <Row k="Ports" v={<span className="text-low">{displayPorts.length}</span>} />
                {findingsTotal > 0 && <Row k="Vulnerabilities" v={<span className="text-high">{findingsTotal}</span>} />}
                {displayVulns.length > 0 && (
                  <Row k="Catalog leads" v={
                    <span className="text-text-dim" title="Banner/version catalog matches — filtered, not confirmed vulnerabilities. Related CVE IDs may appear under each lead.">
                      {displayVulns.length} filtered
                    </span>
                  } />
                )}
                {(sections.aiAgent?.confirmed ?? 0) > 0 && (
                  <Row k="Confirmed" v={<span className="text-critical">{sections.aiAgent!.confirmed}</span>} />
                )}
              </dl>
            </div>
          </div>
        </aside>
      </div>
    </div>
  )
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-2">
      <dt className="text-text-dim shrink-0">{k}</dt>
      <dd className="text-text-bright text-right truncate">{v}</dd>
    </div>
  )
}

function Flag({ label }: { label: string }) {
  return (
    <span className="inline-block text-[10px] bg-accent/10 text-accent border border-accent/20 rounded px-1.5 py-0.5 mr-1 mb-1">
      {label}
    </span>
  )
}

// Top-level tab (Summary / Data) — underline-style, sits directly under the header.
function TabBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-2 text-[13px] border-b-2 -mb-px transition-colors ${
        active
          ? 'border-accent text-text-bright font-medium'
          : 'border-transparent text-text-dim hover:text-text'
      }`}
    >
      {children}
    </button>
  )
}

// Executive / Technical sub-tab within the Summary tab.
function SubTabBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1.5 text-[12px] border-b-2 -mb-px transition-colors ${
        active
          ? 'border-accent text-accent font-medium'
          : 'border-transparent text-text-dim hover:text-text'
      }`}
    >
      {children}
    </button>
  )
}
