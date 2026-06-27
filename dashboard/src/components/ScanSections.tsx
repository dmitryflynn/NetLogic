import { useEffect, useRef } from 'react'
import type { ScanSections, FusionRow } from '../api/scan'
import Markdown from './Markdown'

const SEV: Record<string, string> = {
  CRITICAL: 'text-critical', HIGH: 'text-high', MEDIUM: 'text-medium',
  LOW: 'text-low', INFO: 'text-text-dim',
}

const DECISION: Record<string, { label: string; cls: string }> = {
  confirmed: { label: 'CONFIRMED', cls: 'text-low border-low/40' },
  potential: { label: 'POTENTIAL · verify', cls: 'text-medium border-medium/40' },
}

function FusionFinding({ r }: { r: FusionRow }) {
  const sev = SEV[(r.impact || '').toUpperCase()] ?? 'text-text-dim'
  const d = DECISION[r.decision]
  return (
    <div className="border-b border-border/40 pb-2 last:border-0">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`text-[10px] font-bold uppercase ${sev}`}>{r.impact}</span>
        <span className="text-text-bright font-mono break-all">{r.subject}</span>
        {r.port != null && <span className="text-text-dim">:{r.port}</span>}
        {d && <span className={`text-[10px] px-1.5 py-0.5 rounded border ${d.cls}`}>{d.label}</span>}
        {r.pinned && <span className="text-[10px] text-accent" title="Pinned: KEV / probe-confirmed — never dropped">★ pinned</span>}
        {r.agreement > 1 && <span className="text-[10px] text-text-dim">{r.agreement}× corroborated</span>}
        {r.safety_override && (
          <span className="text-[10px] text-high" title="AI judged it a false positive but it's high-impact → kept for verification (never auto-dropped)">held</span>
        )}
      </div>
      {r.ai?.reason
        ? <p className="text-text-dim mt-0.5 text-[11px]">AI: {r.ai.reason}</p>
        : (r.rationale && <p className="text-text-dim mt-0.5 text-[11px]">{r.rationale}</p>)}
    </div>
  )
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <p className="section-title mb-3">{title}</p>
      <div className="panel border border-border rounded-lg p-4 space-y-2 text-[12px]">{children}</div>
    </section>
  )
}

function KV({ k, v }: { k: string; v: React.ReactNode }) {
  if (v == null || v === '' || (Array.isArray(v) && v.length === 0)) return null
  return (
    <div className="flex gap-2">
      <span className="text-text-dim shrink-0 w-32">{k}</span>
      <span className="text-text-bright break-all">{v}</span>
    </div>
  )
}

export default function ScanSections({ s, onExplore, exploreMd, exploring }: {
  s: ScanSections
  onExplore?: (finding: string) => void
  exploreMd?: Record<string, string>
  exploring?: string | null
}) {
  const arr = (x: unknown) => (Array.isArray(x) ? (x as Record<string, unknown>[]) : [])
  const str = (x: unknown) => (x == null ? '' : String(x))
  const deepDiveRef = useRef<HTMLDivElement | null>(null)

  // Scroll deep-dive section into view when a new elaboration arrives
  useEffect(() => {
    if (exploreMd && Object.keys(exploreMd).length > 0 && deepDiveRef.current) {
      deepDiveRef.current.lastElementChild?.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    }
  }, [exploreMd])

  return (
    <>
      {/* ── AI Analysis ── */}
      {s.ai && (s.ai.markdown || s.ai.error) && (
        <Panel title={`AI Analyst${s.ai.model ? ` · ${s.ai.provider}/${s.ai.model}` : ''}`}>
          {s.ai.error
            ? <p className="text-high">⚠ {s.ai.error}</p>
            : <Markdown text={s.ai.markdown ?? ''} onExplore={onExplore} exploring={exploring} />}
          {/* Inline explore elaborations (Beyond CVEs deep-dives) */}
          {exploreMd && Object.entries(exploreMd).length > 0 && (
            <div ref={deepDiveRef} className="mt-3 border-t border-border pt-3 space-y-3">
              {Object.entries(exploreMd).map(([finding, md]) => (
                <div key={finding} className="border border-accent/20 rounded p-3 bg-elevated/50">
                  <p className="text-[11px] text-text-dim mb-1">⟐ Deep dive: {finding}</p>
                  <Markdown text={md} exploring={exploring} />
                </div>
              ))}
            </div>
          )}
          {exploring && <p className="text-[11px] text-text-dim mt-2 italic">⟐ Exploring…</p>}
        </Panel>
      )}

      {/* ── Fusion: gate + AI adjudicated findings ── */}
      {s.fusion && (s.fusion.summary?.confirmed + s.fusion.summary?.potential + s.fusion.summary?.discarded) > 0 && (
        <Panel title="Fusion — Adjudicated Findings">
          <div className="flex gap-3 text-[11px] flex-wrap pb-1 border-b border-border/40">
            <span className="text-low">✓ {s.fusion.summary.confirmed} confirmed</span>
            <span className="text-medium">? {s.fusion.summary.potential} potential</span>
            <span className="text-text-dim">✕ {s.fusion.summary.discarded} filtered as noise</span>
            {s.fusion.summary.ai_adjudicated > 0 && (
              <span className="text-accent">{s.fusion.summary.ai_adjudicated} AI-judged</span>
            )}
          </div>
          {[...(s.fusion.confirmed ?? []), ...(s.fusion.potential ?? [])].map((r, i) => (
            <FusionFinding key={i} r={r} />
          ))}
          {(s.fusion.confirmed?.length ?? 0) + (s.fusion.potential?.length ?? 0) === 0 && (
            <p className="text-text-dim text-[11px]">
              All {s.fusion.summary.discarded} signal(s) filtered as noise — nothing met the confirmation bar.
            </p>
          )}
        </Panel>
      )}

      {/* ── Change since last scan ── (has_changes is a Python @property dropped by
            asdict, so detect changes from the arrays directly) ── */}
      {s.scanDiff && (
        (s.scanDiff.ports_added as unknown[] | undefined)?.length ||
        (s.scanDiff.ports_removed as unknown[] | undefined)?.length ||
        (s.scanDiff.version_changes as unknown[] | undefined)?.length ||
        (s.scanDiff.cves_added as unknown[] | undefined)?.length
      ) && (
        <Panel title="Changes Since Last Scan">
          {arr((s.scanDiff as Record<string, unknown>).cves_added).map((c, i) => (
            <p key={`ca${i}`} className="text-critical">+ NEW CVE {str(c.cve)} on port {str(c.port)}</p>
          ))}
          {arr((s.scanDiff as Record<string, unknown>).version_changes).map((c, i) => (
            <p key={`vc${i}`} className="text-medium">~ port {str(c.port)}: {str(c.old)} → {str(c.new)}</p>
          ))}
          {(s.scanDiff.ports_added as number[] | undefined ?? []).map((p, i) => (
            <p key={`pa${i}`} className="text-low">+ port {p} now open</p>
          ))}
          {(s.scanDiff.ports_removed as number[] | undefined ?? []).map((p, i) => (
            <p key={`pr${i}`} className="text-text-dim">- port {p} closed</p>
          ))}
        </Panel>
      )}

      {/* ── Service exploitability ── */}
      {s.exploitability && arr(s.exploitability.attributes).length > 0 && (
        <Panel title="Service Exploitability (Preconditions)">
          {arr(s.exploitability.attributes).map((a, i) => (
            <div key={i} className="border-b border-border/40 pb-2 last:border-0">
              <div className="flex items-center gap-2">
                <span className={`text-[10px] font-bold uppercase ${SEV[str(a.severity).toUpperCase()] ?? 'text-text-dim'}`}>
                  {str(a.severity)}
                </span>
                <span className="text-text-dim">port {str(a.port)}/{str(a.service)}</span>
                <span className="text-text-bright font-mono">{str(a.attribute)}={str(a.value)}</span>
              </div>
              <p className="text-text-dim mt-0.5">{str(a.detail)}</p>
              {arr(a.exploit_precondition_for).length > 0 && (
                <p className="text-accent text-[11px]">→ precondition for: {(a.exploit_precondition_for as string[]).join(', ')}</p>
              )}
            </div>
          ))}
        </Panel>
      )}

      {/* ── Authenticated (ground truth) ── */}
      {s.authenticated && Boolean(s.authenticated.success) && (
        <Panel title="Authenticated Scan — Installed Versions (Ground Truth)">
          <KV k="OS" v={str(s.authenticated.os_name)} />
          <KV k="Kernel" v={str(s.authenticated.kernel)} />
          {Object.entries((s.authenticated.product_versions as Record<string, Record<string, unknown>>) ?? {}).map(([prod, info]) => (
            <div key={prod} className="flex gap-2">
              <span className="text-accent shrink-0 w-28 font-mono">{prod}</span>
              <span className="text-text-bright font-mono">{str(info.upstream)}</span>
              <span className="text-text-dim font-mono">{str(info.full)}</span>
              {Boolean(info.backported) && <span className="text-low text-[11px]">[backported — likely patched]</span>}
            </div>
          ))}
        </Panel>
      )}

      {/* ── Web fingerprint ── */}
      {s.webFingerprint && (
        <Panel title="Web Application Fingerprint">
          <KV k="Title" v={str(s.webFingerprint.title)} />
          <KV k="Generator" v={str(s.webFingerprint.generator)} />
          <KV k="Favicon hash" v={s.webFingerprint.favicon_mmh3 != null ? str(s.webFingerprint.favicon_mmh3) : ''} />
          <KV k="Versions" v={(s.webFingerprint.version_markers as string[] | undefined ?? []).join(', ')} />
          <KV k="Exposed files" v={<span className="text-high">{(s.webFingerprint.exposed_files as string[] | undefined ?? []).join(', ')}</span>} />
          <KV k="JS endpoints" v={(s.webFingerprint.js_endpoints as string[] | undefined ?? []).slice(0, 8).join(', ')} />
          {(s.webFingerprint.js_secrets as string[] | undefined ?? []).length > 0 && (
            <KV k="JS secrets" v={<span className="text-critical">{(s.webFingerprint.js_secrets as string[]).join(', ')}</span>} />
          )}
        </Panel>
      )}

      {/* ── Topology ── */}
      {s.topology && (
        <Panel title="Network Topology">
          <KV k="Reverse DNS" v={str(s.topology.ptr)} />
          <KV k="ASN" v={[s.topology.asn, s.topology.asn_org, s.topology.country].filter(Boolean).map(str).join(' · ')} />
          <KV k="IPv6" v={(s.topology.ipv6 as string[] | undefined ?? []).slice(0, 3).join(', ')} />
          <KV k="Hops" v={s.topology.hop_count != null ? str(s.topology.hop_count) : ''} />
        </Panel>
      )}

      {/* ── TLS summary ── */}
      {s.tls && arr(s.tls.results).length > 0 && (
        <Panel title="TLS / Certificate">
          {arr(s.tls.results).map((t, i) => {
            const cert = (t.cert as Record<string, unknown>) ?? {}
            return (
              <div key={i} className="space-y-1">
                <KV k={`Port ${str(t.port)} grade`} v={str(t.grade)} />
                <KV k="Protocols" v={(t.protocols_supported as string[] | undefined ?? []).join(', ')} />
                <KV k="Deprecated" v={<span className="text-high">{(t.protocols_deprecated as string[] | undefined ?? []).join(', ')}</span>} />
                <KV k="Cert expires" v={cert.not_after ? `${str(cert.not_after)} (${str(cert.days_until_expiry)}d)` : ''} />
                <KV k="Cert SANs" v={(cert.san_domains as string[] | undefined ?? []).slice(0, 8).join(', ')} />
              </div>
            )
          })}
        </Panel>
      )}
    </>
  )
}
