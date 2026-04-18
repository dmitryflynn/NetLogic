import { useParams, useNavigate } from 'react-router-dom'
import { useJob, useCancelJob, useStreamScan, type PortEvent, type VulnEvent } from '../api/scan'
import StatusBadge from '../components/StatusBadge'
import PortTable from '../components/PortTable'
import VulnCard from '../components/VulnCard'
import ScanFeed from '../components/ScanFeed'

function fmtDate(ts: number | null) {
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const nav    = useNavigate()
  const { data: job, isLoading } = useJob(id!)
  const cancel = useCancelJob()

  // SSE stream — only active while job is running/queued
  const live = (job?.status === 'running' || job?.status === 'queued')
  const { events, ports, vulns, progress, streaming } = useStreamScan(live ? id! : null)

  // For completed jobs, pull ports/vulns from stored events.
  // The scan engine emits vulns as {port, service, cves:[{id, cvss_score,...}]};
  // normalise to the flat VulnEvent shape the UI expects.
  const storedPorts = (job?.events ?? [])
    .filter((e) => e.type === 'port')
    .map((e) => e.data as PortEvent)

  const storedVulns: VulnEvent[] = (job?.events ?? [])
    .filter((e) => e.type === 'vuln')
    .flatMap((e) => {
      const d = e.data as Record<string, unknown> | undefined
      if (!d) return []
      // Nested engine format: {port, service, cves:[...]}
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
        } satisfies VulnEvent))
      }
      // Already-flat format
      return [d as unknown as VulnEvent]
    })

  const displayPorts = live ? ports  : storedPorts
  const displayVulns = live ? vulns  : storedVulns
  const displayPct   = live ? (progress?.percent ?? job?.progress ?? 0) : (job?.progress ?? 0)

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

          {/* Open Ports */}
          {displayPorts.length > 0 && (
            <section>
              <p className="section-title mb-3">
                Open Ports ({displayPorts.length})
              </p>
              <PortTable ports={displayPorts} />
            </section>
          )}

          {/* Vulnerabilities */}
          {displayVulns.length > 0 && (
            <section>
              <p className="section-title mb-3">
                Vulnerabilities ({displayVulns.length})
              </p>
              <div className="space-y-2">
                {displayVulns
                  .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))
                  .map((v, i) => (
                    <VulnCard key={`${v.cve_id}-${i}`} vuln={v} />
                  ))}
              </div>
            </section>
          )}

          {/* Live feed while scanning */}
          {live && events.length > 0 && (
            <section>
              <p className="section-title mb-3">Live Events</p>
              <ScanFeed events={events} />
            </section>
          )}

          {displayPorts.length === 0 && displayVulns.length === 0 &&
           !live && job.status === 'completed' && (
            <p className="text-text-dim text-[12px] text-center mt-8">
              No open ports or vulnerabilities found.
            </p>
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
              </dl>
            </div>

            <div>
              <p className="section-title mb-2">Results</p>
              <dl className="space-y-1.5 text-[11px]">
                <Row k="Ports" v={<span className="text-low">{displayPorts.length}</span>} />
                <Row k="Vulns" v={<span className="text-critical">{displayVulns.length}</span>} />
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
