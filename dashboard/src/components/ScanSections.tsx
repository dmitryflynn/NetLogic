import { useEffect, useRef } from 'react'
import type { ScanSections, SaaSHit } from '../api/scan'
import Markdown from './Markdown'

const SEV: Record<string, string> = {
  CRITICAL: 'text-critical', HIGH: 'text-high', MEDIUM: 'text-medium',
  LOW: 'text-low', INFO: 'text-text-dim',
}

function Panel({ title, subtitle, children, collapsible, defaultOpen = true }: {
  title: string; subtitle?: string; children: React.ReactNode
  collapsible?: boolean; defaultOpen?: boolean
}) {
  if (collapsible) {
    // Deep-dive panels (the "how") collapse so the conclusions stay the primary view — the same
    // entities aren't repeated in the reader's face across objectives/hypotheses/plans/graph.
    return (
      <section>
        <details open={defaultOpen} className="group">
          <summary className="section-title mb-3 cursor-pointer select-none list-none flex items-center gap-2 hover:text-text">
            <span className="text-text-dim text-[10px] transition-transform group-open:rotate-90">▶</span>
            {title}
            {subtitle && <span className="text-text-dim font-normal normal-case tracking-normal text-[11px]">· {subtitle}</span>}
          </summary>
          <div className="panel border border-border rounded-lg p-4 space-y-2 text-[12px]">{children}</div>
        </details>
      </section>
    )
  }
  return (
    <section>
      <p className="section-title mb-3">{title}{subtitle && <span className="text-text-dim font-normal normal-case tracking-normal text-[11px]"> · {subtitle}</span>}</p>
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

/** Split the AI-analyst markdown into its Executive-Summary section vs. the detailed technical
 *  sections (Findings/PoC/Attack Chains/Beyond CVEs/Remediation) for the Summary tabs. */
function splitAiMarkdown(md: string): { exec: string; technical: string } {
  const lines = (md || '').split('\n')
  const exec: string[] = []
  const tech: string[] = []
  let cur: 'exec' | 'tech' = 'exec'      // content before the first ## goes with the exec summary
  for (const line of lines) {
    const h = /^##\s+(.*)$/.exec(line)
    if (h) cur = h[1].trim().toLowerCase().startsWith('executive summary') ? 'exec' : 'tech'
    ;(cur === 'exec' ? exec : tech).push(line)
  }
  return { exec: exec.join('\n').trim(), technical: tech.join('\n').trim() }
}

export default function ScanSections({ s, onExplore, exploreMd, exploring, view }: {
  s: ScanSections
  onExplore?: (finding: string) => void
  exploreMd?: Record<string, string>
  exploring?: string | null
  /** Tab gating: which group of panels to render. Undefined = render all (legacy / tests). */
  view?: 'executive' | 'technical' | 'data'
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

  const PRIO: Record<string, string> = {
    P1: 'text-rose-400 border-rose-500/40 bg-rose-500/10',
    P2: 'text-amber-400 border-amber-500/40 bg-amber-500/10',
    P3: 'text-amber-300 border-amber-400/30 bg-amber-400/5',
    P4: 'text-text-dim border-border', P5: 'text-text-dim border-border',
  }

  const ROLE_ORDER = ['frontend', 'hosting', 'cdn', 'waf', 'server', 'auth', 'backend', 'payments', 'analytics', 'monitoring', 'email', 'language', 'cloud']
  // Plan B: Top Findings + Findings Detail lead; engine panels collapse when
  // triage or investigations already own the story (kill CVE re-lists).
  const hasTriage = ((s.triage?.attention?.length ?? 0) + (s.triage?.noise?.length ?? 0)) > 0
  const hasInvestigations = (s.investigations?.length ?? 0) > 0
  const collapseAdvanced = hasTriage || hasInvestigations
  // Tab gating: undefined view renders everything (unit tests / legacy callers).
  const inView = (v: 'executive' | 'technical' | 'data') => !view || view === v

  return (
    <>
      {/* ── Vulnerabilities first (verdict); catalog version-leads stay filtered ── */}
      {inView('executive') && hasTriage && (
        <Panel title="Vulnerabilities"
               subtitle={(s.triage!.attention?.length ?? 0) > 0
                 ? `${s.triage!.attention!.length} worth attention · ${s.triage!.noise?.length ?? 0} catalog leads filtered`
                 : `no verified vulnerabilities · ${s.triage!.noise?.length ?? 0} catalog lead(s) filtered`}>
          {(s.triage!.attention?.length ?? 0) === 0 ? (
            <p className="text-[12px] text-emerald-400">
              ✓ No verified high-priority vulnerabilities. {s.triage!.noise?.length ?? 0} version/catalog
              lead(s) were filtered — not reported as vulnerabilities (patch level
              unverifiable from a version string alone).
            </p>
          ) : (
            <div className="space-y-2">
              {s.triage!.attention!.map((t, i) => (
                <div key={i} className="flex items-start gap-2 text-[12px] border-b border-border/30 pb-2 last:border-0">
                  <span className={`shrink-0 text-[10px] font-bold px-1.5 py-0.5 rounded border ${PRIO[t.priority ?? 'P5'] ?? PRIO.P5}`}>
                    {t.priority}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-text-bright font-medium">{t.title || t.cve || 'Vulnerability'}</span>
                      {t.kind === 'web' && <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-accent/15 text-accent border border-accent/30 uppercase">SaaS</span>}
                      {t.kind !== 'web' && t.cvss != null && t.cvss > 0 && <span className="text-text-dim text-[10px]">CVSS {t.cvss.toFixed(1)}</span>}
                      {t.kev && <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 uppercase">KEV</span>}
                      {t.exploit_available && !t.kev && <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40 uppercase">exploit</span>}
                      {t.kind !== 'web' && (t.service || t.port) && <span className="text-text-dim text-[10px]">{t.service}{t.port ? `:${t.port}` : ''}</span>}
                    </div>
                    {t.cve && (
                      <p className="text-text-dim text-[10px] mt-0.5 font-mono">
                        Related: <span className="text-text-dim/90">{t.cve}</span>
                      </p>
                    )}
                    <p className="text-text-dim text-[11px] mt-0.5">{t.rationale}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
          {(s.triage!.noise?.length ?? 0) > 0 && (
            <details className="mt-2 group">
              <summary className="text-[11px] text-text-dim cursor-pointer select-none hover:text-text">
                <span className="inline-block transition-transform group-open:rotate-90">▶</span>{' '}
                {s.triage!.noise!.length} catalog lead(s) filtered (not vulnerabilities)
              </summary>
              <ul className="mt-1 space-y-0.5">
                {s.triage!.noise!.map((t, i) => (
                  <li key={i} className="text-[11px] text-text-dim flex flex-col gap-0.5 sm:flex-row sm:items-center sm:gap-2">
                    <span className="text-text-dim">{t.title || 'Catalog lead'}</span>
                    {t.cve && <span className="font-mono text-[10px] text-text-dim/80">({t.cve})</span>}
                    <span className="text-text-dim/70">{t.rationale}</span>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </Panel>
      )}

      {/* ── Architecture Summary — structure-first: consume it in 5s, narrative is optional below ── */}
      {inView('executive') && (s.architecture?.components?.length ?? 0) > 0 && (() => {
        const arch = s.architecture!
        const ROLE_LABEL: Record<string, string> = {
          frontend: 'Frontend', hosting: 'Hosting', cdn: 'CDN', waf: 'WAF', server: 'Server',
          auth: 'Authentication', backend: 'Backend', payments: 'Payments', analytics: 'Analytics',
          monitoring: 'Monitoring', email: 'Email', language: 'Language', cloud: 'Cloud',
        }
        const comps = [...(arch.components ?? [])].sort(
          (a, b) => ROLE_ORDER.indexOf(a.role ?? '') - ROLE_ORDER.indexOf(b.role ?? ''))
        const confCls = (c: number) => c >= 95 ? 'text-low' : c >= 80 ? 'text-medium' : 'text-text-dim'
        return (
        <Panel title="Architecture Summary">
          {/* Structured, scannable — one row per component with a deterministic confidence. */}
          <div className="space-y-1">
            {comps.map((c, i) => (
              <div key={i} className="flex items-baseline gap-3 text-[12px]" title={c.evidence}>
                <span className="text-text-dim uppercase tracking-wide text-[10px] w-28 shrink-0">{ROLE_LABEL[c.role ?? ''] ?? c.role}</span>
                <span className="text-text-bright flex-1">{c.name}</span>
                {c.confidence != null && <span className={`text-[10px] font-mono ${confCls(c.confidence)}`}>{c.confidence}%</span>}
              </div>
            ))}
            {arch.execution_model && (
              <div className="flex items-baseline gap-3 text-[12px] pt-1 border-t border-border/30">
                <span className="text-text-dim uppercase tracking-wide text-[10px] w-28 shrink-0">Execution model</span>
                <span className="text-text-bright flex-1">{arch.execution_model}</span>
              </div>
            )}
          </div>

          {(arch.attack_surfaces?.length ?? 0) > 0 && (
            <div className="mt-3">
              <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">Primary attack surfaces</p>
              <ul className="space-y-0.5">
                {arch.attack_surfaces!.map((a, i) => (
                  <li key={i} className="text-[11px] text-text flex items-start gap-1.5">
                    <span className="text-accent">›</span>{a}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {arch.narrative && (
            <details className="mt-3 group">
              <summary className="text-[10px] text-text-dim uppercase tracking-wide cursor-pointer select-none hover:text-text">
                <span className="inline-block transition-transform group-open:rotate-90">▶</span> Narrative
              </summary>
              <p className="text-[12px] text-text-dim leading-relaxed mt-1">{arch.narrative}</p>
            </details>
          )}
        </Panel>
        )
      })()}

      {/* ── AI Investigation Plan — advanced / collapsed when report already has a verdict ── */}
      {inView('executive') && (s.investigationPlan?.length ?? 0) > 0 && (
        <Panel title="Investigation Plan" subtitle="priorities only — not findings"
               collapsible defaultOpen={!collapseAdvanced}>
          <p className="text-text-dim text-[11px] mb-2">
            Highest-value review targets derived from detected components. No vulnerabilities claimed.
          </p>
          <div className="space-y-2">
            {s.investigationPlan!.map((o, i) => (
              <div key={i} className="flex items-start gap-2 text-[12px] border-b border-border/30 pb-2 last:border-0">
                <span className="shrink-0 text-[10px] font-bold px-1.5 py-0.5 rounded border border-accent/40 text-accent bg-accent/10">
                  {i + 1}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-text font-medium">{o.title}</span>
                    {o.component && (
                      <span className="text-[9px] px-1 py-0.5 rounded border border-border text-text-dim uppercase tracking-wide">
                        {o.component}
                      </span>
                    )}
                  </div>
                  {o.reason && <p className="text-text-dim text-[11px] mt-0.5">{o.reason}</p>}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* ── AI Analysis — Executive Summary (exec view) vs full technical breakdown (technical view) ── */}
      {!inView('data') && s.ai && (s.ai.markdown || s.ai.error) && (() => {
        if (s.ai.error) {
          return <Panel title="AI Analyst"><p className="text-high">⚠ {s.ai.error}</p></Panel>
        }
        const { exec, technical } = splitAiMarkdown(s.ai.markdown ?? '')
        // executive view → Executive Summary section; technical view → the detailed sections;
        // no view (tests/legacy) → the whole report.
        const md = view === 'executive' ? exec : view === 'technical' ? technical : (s.ai.markdown ?? '')
        if (!md) return null
        const title = view === 'technical' ? 'Technical Analysis' : 'Executive Summary'
        const showExplore = view !== 'executive'   // Beyond-CVEs deep dives live in the technical view
        return (
        <Panel title={`${title}${s.ai.model ? ` · ${s.ai.provider}/${s.ai.model}` : ''}`}>
          <Markdown text={md} onExplore={showExplore ? onExplore : undefined} exploring={exploring} />
          {showExplore && exploreMd && Object.entries(exploreMd).length > 0 && (
            <div ref={deepDiveRef} className="mt-3 border-t border-border pt-3 space-y-3">
              {Object.entries(exploreMd).map(([finding, dm]) => (
                <div key={finding} className="border border-accent/20 rounded p-3 bg-elevated/50">
                  <p className="text-[11px] text-text-dim mb-1">⟐ Deep dive: {finding}</p>
                  <Markdown text={dm} exploring={exploring} />
                </div>
              ))}
            </div>
          )}
          {showExplore && exploring && <p className="text-[11px] text-text-dim mt-2 italic">⟐ Exploring…</p>}
        </Panel>
        )
      })()}

      {/* ── Findings detail (investigations) — open when it's the main technical list ── */}
      {inView('technical') && (s.investigations?.length ?? 0) > 0 && (() => {
        const adjudicated = s.investigations!.filter((iv) => iv.adjudicated_by_ai).length
        // Prefer investigations that reached a real verdict; UNVERIFIED pattern leads last
        const sorted = [...s.investigations!].sort((a, b) => {
          const rank = (c: string) => {
            const u = (c || '').toUpperCase()
            if (u === 'UNVERIFIED') return 3
            if (u.includes('NOT EXPLOITABLE') || u === 'REFUTED') return 1
            if (u === 'EXPLOITABLE' || u.startsWith('CONFIRMED')) return 0
            return 2
          }
          return rank(a.conclusion ?? '') - rank(b.conclusion ?? '')
        })
        return (
        <Panel title="Vulnerability detail"
               collapsible defaultOpen={!hasTriage || (s.triage?.attention?.length ?? 0) > 0}
               subtitle={adjudicated > 0 ? `${adjudicated} AI-resolved` : undefined}>
          <p className="text-text-dim text-[11px] mb-3">
            One card per investigated vulnerability with evidence. Version/banner catalog matches without
            a non-destructive remote proof stay <span className="text-slate-400">UNVERIFIED</span> (leads,
            not confirmed vulnerabilities). Related CVE identifiers may appear in the evidence — the
            primary object is the weakness on this host, not the catalog ID.
          </p>
          <div className="space-y-3">
            {sorted.map((iv, i) => {
              const c = (iv.conclusion ?? '').toUpperCase()
              const tone =
                c === 'UNVERIFIED' ? 'text-slate-400 border-slate-500/30'
                : c.includes('NOT EXPLOITABLE') || c === 'REFUTED' ? 'text-emerald-400 border-emerald-500/30'
                : c === 'EXPLOITABLE' || c.startsWith('CONFIRMED') ? 'text-rose-400 border-rose-500/30'
                : c.includes('POSSIBLY') || c.startsWith('LIKELY') ? 'text-amber-400 border-amber-500/30'
                : 'text-text-dim border-border'
              return (
                <div key={i} className={`rounded border ${tone} bg-black/20 p-3`}>
                  <div className="flex items-start justify-between gap-3">
                    <p className="text-text font-medium text-[13px]">{iv.question}</p>
                    <span className={`shrink-0 text-[11px] font-semibold ${tone.split(' ')[0]} flex items-center gap-1`}>
                      {iv.adjudicated_by_ai && (
                        <span className="text-[9px] font-bold px-1 py-0.5 rounded bg-accent/20 text-accent border border-accent/40 uppercase tracking-wide"
                              title="Resolved by the AI where the deterministic engine had no sensor to verify it">
                          AI
                        </span>
                      )}
                      {iv.conclusion}
                    </span>
                  </div>
                  {iv.adjudicated_by_ai && iv.rationale && (
                    <p className="mt-1 text-[11px] text-accent/90">AI: {iv.rationale}</p>
                  )}
                  <div className="mt-1 flex items-center gap-3 text-[10px] text-text-dim">
                    <span>confidence {(iv.confidence ?? 0).toFixed(2)}</span>
                    <span>evidence {iv.gathered ?? 0}/{iv.total_evidence ?? iv.evidence?.length ?? 0}</span>
                    {iv.kind && <span className="uppercase tracking-wide">{iv.kind}</span>}
                  </div>
                  {(iv.evidence?.length ?? 0) > 0 && (
                    <ul className="mt-2 space-y-0.5">
                      {iv.evidence!.map((e, j) => (
                        <li key={j} className="text-[11px] flex items-center gap-1.5">
                          <span className={e.satisfied ? 'text-emerald-400' : 'text-text-dim'}>
                            {e.satisfied ? '✓' : '○'}
                          </span>
                          <span className={e.satisfied ? 'text-text' : 'text-text-dim'}>{e.name}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )
            })}
          </div>
        </Panel>
        )
      })()}

      {/* ── Reasoning Engine (the "how" — collapsed so the conclusions above stay primary) ── */}
      {inView('data') && s.reasoning?.reasoning_enabled && (
        <Panel title="Reasoning Engine" collapsible defaultOpen={false}
               subtitle="how it got there — objectives, hypotheses, evidence graph, plans">
          {(() => {
            const r = s.reasoning!
            const inv = r.investigation
            const exec = r.execution
            const world = r.world
            const steps = exec?.execution_history ?? []
            const probeCount = exec?.probe_history?.length ?? 0
            const objectives = inv?.objectives ?? []
            const hypotheses = inv?.hypotheses ?? []
            const nodes = world?.graph?.nodes ?? []
            const beliefs = world?.beliefs ?? {}
            const contradictions = inv?.contradictions ?? []
            const deadEnds = inv?.dead_ends ?? []
            const provEdges = (exec?.provenance?.edges as unknown[] | undefined)?.length ?? 0
            const satisfied = objectives.filter((o) => o.satisfied).length
            // Group evidence-graph nodes by kind for a compact view.
            const byKind = nodes.reduce<Record<string, typeof nodes>>((acc, n) => {
              const k = n.kind ?? 'node'; (acc[k] ??= []).push(n); return acc
            }, {})
            return (
              <>
                <div className="flex gap-3 text-[11px] flex-wrap pb-1 border-b border-border/40">
                  <span className="text-accent">{inv?.persona ?? '—'} persona</span>
                  <span className="text-text-dim">{steps.length} steps · {probeCount} probes</span>
                  <span className="text-text-dim">{nodes.length} entities · {objectives.length} objectives</span>
                  {provEdges > 0 && <span className="text-text-dim">{provEdges} provenance links</span>}
                  {r.world_modeling_enabled && <span className="text-low">multi-host</span>}
                </div>

                {/* Objectives DAG — what the engine decided to investigate */}
                {objectives.length > 0 && (
                  <div className="mt-2">
                    <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">
                      Objectives <span className="text-low">{satisfied}</span>/{objectives.length} satisfied
                    </p>
                    <div className="space-y-0.5">
                      {objectives.slice(0, 12).map((o, i) => (
                        <div key={i} className="flex items-center gap-2 text-[11px]">
                          <span className={o.satisfied ? 'text-low' : 'text-text-dim'}>{o.satisfied ? '✓' : '○'}</span>
                          <span className="text-text-bright font-mono text-[10px] break-all">{o.name}</span>
                          {typeof o.priority === 'number' && (
                            <span className="text-text-dim text-[10px]">p={o.priority.toFixed(2)}</span>
                          )}
                          {o.source?.generated_by && o.source.generated_by !== 'generator' && (
                            <span className="text-accent text-[10px]">{o.source.generated_by}</span>
                          )}
                        </div>
                      ))}
                      {objectives.length > 12 && <p className="text-[10px] text-text-dim">… and {objectives.length - 12} more</p>}
                    </div>
                  </div>
                )}

                {/* Hypotheses — competing explanations; posterior derived from likelihoods */}
                {hypotheses.length > 0 && (
                  <div className="mt-2">
                    <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">Hypotheses</p>
                    {hypotheses.slice(0, 8).map((h, i) => {
                      const likes = h.likelihoods ?? {}
                      const total = Object.values(likes).reduce((a, b) => a + b, 0) || 1
                      const [lead, leadP] = Object.entries(likes)
                        .sort((a, b) => b[1] - a[1])[0] ?? ['—', 0]
                      return (
                        <div key={i} className="flex items-center gap-2 text-[11px]">
                          <span className="text-text-bright break-all">{h.label ?? h.id}</span>
                          {lead !== '—' && (
                            <span className={leadP / total >= 0.5 ? 'text-medium' : 'text-text-dim'}>
                              {lead} {((leadP / total) * 100).toFixed(0)}%
                            </span>
                          )}
                          {h.status && h.status !== 'active' && (
                            <span className="text-[10px] text-low">{h.status}</span>
                          )}
                        </div>
                      )
                    })}
                  </div>
                )}

                {/* Investigation plans (Phase 8) — read-only goal-directed chains the planner built */}
                {(exec?.investigation_plans?.length ?? 0) > 0 && (
                  <div className="mt-2">
                    <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">
                      Investigation Plans <span className="text-text-dim/70">(read-only · analysis)</span>
                    </p>
                    {exec!.investigation_plans!.slice(0, 8).map((p, i) => (
                      <div key={i} className="border-l border-border/40 pl-2 py-0.5 mb-1">
                        <div className="flex items-center gap-2 text-[11px]">
                          <span className={p.goal_reachable ? 'text-low' : 'text-medium'}>
                            {p.goal_reachable ? '✓ reachable' : '◐ partial'}
                          </span>
                          <span className="text-text-bright font-mono text-[10px] break-all">{p.objective}</span>
                          {p.max_risk_tier && <span className="text-[10px] text-text-dim">{p.max_risk_tier}</span>}
                        </div>
                        {(p.steps?.length ?? 0) > 0 && (
                          <p className="text-[10px] text-accent/80 font-mono break-all">
                            {p.steps!.map((st) => st.action_id).join(' → ')}
                          </p>
                        )}
                        {(p.unmet_preconditions?.length ?? 0) > 0 && (
                          <p className="text-[10px] text-text-dim">needs: {p.unmet_preconditions!.join(', ')}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Evidence graph — the immutable ground truth, grouped by entity kind */}
                {nodes.length > 0 && (
                  <div className="mt-2">
                    <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">Evidence Graph</p>
                    <div className="space-y-1.5">
                      {Object.entries(byKind).slice(0, 6).map(([kind, ns]) => (
                        <div key={kind}>
                          <p className="text-[10px] text-accent/80">{kind} ({ns.length})</p>
                          {ns.slice(0, 4).map((n, i) => {
                            const conf = n.id ? beliefs[n.id] : undefined
                            const obs = n.observations ?? []
                            return (
                              <div key={i} className="ml-2 border-l border-border/40 pl-2 py-0.5">
                                <div className="flex items-center gap-2 text-[11px]">
                                  <span className="text-text-bright font-mono text-[10px] break-all">{n.label ?? n.key}</span>
                                  {typeof conf === 'number' && (
                                    <span className={conf >= 0.7 ? 'text-low' : conf >= 0.4 ? 'text-medium' : 'text-text-dim'}>
                                      {(conf * 100).toFixed(0)}%
                                    </span>
                                  )}
                                </div>
                                {obs.slice(0, 2).map((o, j) => (
                                  <p key={j} className="text-[10px] text-text-dim truncate" title={o.evidence}>
                                    {o.source ? `[${o.source}] ` : ''}{o.evidence}
                                  </p>
                                ))}
                              </div>
                            )
                          })}
                          {ns.length > 4 && <p className="text-[10px] text-text-dim ml-2">… {ns.length - 4} more {kind}</p>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Contradictions + dead ends — the engine's self-awareness */}
                {contradictions.length > 0 && (
                  <div className="mt-2">
                    <p className="text-[10px] text-high uppercase tracking-wide mb-1">Contradictions</p>
                    {contradictions.slice(0, 4).map((c, i) => (
                      <p key={i} className="text-[11px] text-text-dim">
                        {c.subject}{c.reason ? ` — ${c.reason}` : ''}
                      </p>
                    ))}
                  </div>
                )}

                {/* Loop trace */}
                {steps.length > 0 && (
                  <div className="mt-2">
                    <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">Actions</p>
                    {steps.slice(-6).map((s, i) => (
                      <div key={i} className="flex items-center gap-2 text-[11px]">
                        <span className={s.gained ? 'text-low' : 'text-text-dim'}>{s.gained ? '✓' : '·'}</span>
                        <span className="text-text-bright font-mono text-[10px]">{s.step}</span>
                        {s.rationale && <span className="text-text-dim truncate max-w-[220px]">{s.rationale}</span>}
                      </div>
                    ))}
                    {deadEnds.length > 0 && <p className="text-[10px] text-text-dim mt-0.5">{deadEnds.length} dead-end(s) pruned</p>}
                  </div>
                )}

                {exec?.budget && (
                  <div className="grid grid-cols-3 gap-2 mt-2 pt-2 border-t border-border/40 text-[10px] text-text-dim">
                    <span>time: {Math.round((exec.budget as Record<string, number>).max_wall_clock_s ?? 0)}s</span>
                    <span>probes: {Math.round((exec.budget as Record<string, number>).max_probes ?? 0)}</span>
                    <span>tokens: {(exec.budget as Record<string, number>).max_tokens ?? 0}</span>
                  </div>
                )}
              </>
            )
          })()}</Panel>
      )}

      {/* ── AI Reasoning Replay (Track C — the Investigation Transcript) ── */}
      {(s.reasoning?.execution?.ai_transcript?.entries?.length ?? 0) > 0 && (
        <Panel title="AI Reasoning Replay" collapsible defaultOpen={false}
               subtitle="the proposal-by-proposal trace behind the conclusions above">
          {(() => {
            const t = s.reasoning!.execution!.ai_transcript!
            const sum = t.summary ?? {}
            const OUTCOME: Record<string, string> = {
              confirmed: 'text-low', refuted: 'text-critical', unresolved: 'text-text-dim',
            }
            return (
              <>
                <div className="flex gap-3 text-[11px] flex-wrap pb-1 border-b border-border/40">
                  <span className="text-accent">AI proposes · engine proves</span>
                  <span className="text-text-dim">{sum.proposed ?? 0} proposed · {sum.accepted ?? 0} accepted</span>
                  {(sum.confirmed ?? 0) > 0 && <span className="text-low">{sum.confirmed} confirmed</span>}
                  {(sum.refuted ?? 0) > 0 && <span className="text-critical">{sum.refuted} refuted</span>}
                </div>
                <div className="space-y-1 mt-1">
                  {(t.entries ?? []).slice(0, 12).map((e, i) => (
                    <div key={i} className="border-l border-border/40 pl-2 py-0.5">
                      <div className="flex items-center gap-2 text-[11px] flex-wrap">
                        <span className={e.accepted ? 'text-low' : 'text-text-dim'}>{e.accepted ? '✓' : '✗'}</span>
                        <span className="text-text-bright break-all">{e.summary}</span>
                        <span className="text-[10px] text-text-dim">{e.agent}</span>
                        {e.accepted
                          ? <span className={`text-[10px] ${OUTCOME[e.outcome ?? 'unresolved'] ?? 'text-text-dim'}`}>
                              {e.outcome === 'unresolved' ? e.uncertainty : e.outcome}
                            </span>
                          : <span className="text-[10px] text-medium">rejected @ {e.stage_failed}</span>}
                      </div>
                      {e.rationale && <p className="text-[10px] text-text-dim truncate" title={e.rationale}>{e.rationale}</p>}
                    </div>
                  ))}
                </div>
              </>
            )
          })()}
        </Panel>
      )}

      {/* ── AI Investigation Agent (tool-driven) ── */}
      {inView('technical') && s.aiAgent && ((s.aiAgent.findings?.length ?? 0) > 0 || (s.aiAgent.turns?.length ?? 0) > 0 || (s.aiAgent.chains?.length ?? 0) > 0) && (
        <Panel title="AI Investigation Agent" collapsible defaultOpen={(s.aiAgent.confirmed ?? 0) > 0 || !!s.aiAgent.depth_mode}
               subtitle={`${s.aiAgent.depth_mode ? 'depth · ' : ''}${s.aiAgent.confirmed ?? 0} confirmed · ${s.aiAgent.high_value_used ?? 0} high-value · ${s.aiAgent.steps_used ?? 0} steps`}>
          <p className="text-[11px] text-text-dim mb-2">
            {s.aiAgent.depth_mode
              ? 'Depth mode: prioritized CVE leads and chains; early stop blocked until high-value work completed.'
              : 'Baseline sensors first; AI chose tools to verify leads and build chains.'}
            {s.aiAgent.stopped_reason && (
              <span className="text-text-dim/80"> Stopped: {s.aiAgent.stopped_reason}.</span>
            )}
          </p>
          {(s.aiAgent.findings?.length ?? 0) > 0 && (
            <div className="space-y-1 mb-2">
              <p className="text-[10px] text-accent uppercase tracking-wide">Findings</p>
              {s.aiAgent.findings!.slice(0, 20).map((f, i) => (
                <div key={i} className="flex items-center gap-2 text-[11px] flex-wrap">
                  <span className={f.status === 'confirmed' ? 'text-low' : 'text-text-dim'}>
                    {f.status === 'confirmed' ? '✓' : '·'}
                  </span>
                  <span className="text-text-bright break-all">{f.title || f.id}</span>
                  {f.severity && <span className="text-[10px] text-high uppercase">{f.severity}</span>}
                  <span className="text-[10px] text-text-dim">{f.status}</span>
                  {f.rationale && <span className="text-[10px] text-text-dim truncate max-w-[280px]">{f.rationale}</span>}
                </div>
              ))}
            </div>
          )}
          {(s.aiAgent.chains?.length ?? 0) > 0 && (
            <div className="space-y-1 mb-2 pt-2 border-t border-border/40">
              <p className="text-[10px] text-accent uppercase tracking-wide">Attack chains</p>
              {s.aiAgent.chains!.slice(0, 15).map((c, i) => (
                <div key={i} className="text-[11px] text-text-bright font-mono">
                  {c.from} <span className="text-accent">→</span> {c.to}
                  {c.why && <span className="text-text-dim font-sans ml-2">{c.why}</span>}
                </div>
              ))}
            </div>
          )}
          {(s.aiAgent.turns?.length ?? 0) > 0 && (
            <details className="mt-1">
              <summary className="text-[10px] text-text-dim cursor-pointer hover:text-text">
                Agent transcript ({s.aiAgent.turns!.length} turns · {s.aiAgent.requests_used ?? 0} network calls)
              </summary>
              <div className="mt-1 space-y-1 max-h-48 overflow-y-auto">
                {s.aiAgent.turns!.map((t, i) => (
                  <div key={i} className="text-[10px] border-l border-border/40 pl-2">
                    <span className="text-text-dim">#{t.step}</span>
                    {t.thought && <span className="text-text-bright ml-1">{t.thought}</span>}
                    {(t.results ?? []).map((r, j) => (
                      <div key={j} className="text-text-dim ml-2">
                        {r.ok === false ? '✗' : '·'} {r.tool}: {r.summary}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </details>
          )}
        </Panel>
      )}

      {/* ── Active Validation (safe_active, gated + audited) ── */}
      {inView('data') && ((s.activeValidation?.results?.length ?? 0) > 0 || (s.activeValidation?.capability_gaps?.length ?? 0) > 0) && (
        <Panel title="Active Validation" collapsible defaultOpen={false}>
          {(() => {
            const av = s.activeValidation!
            const rows = [...(av.results ?? [])].sort((a, b) => {
              // Confirmed first, then executed non-confirmations, then skips/denials.
              const rank = (r: typeof a) => r.succeeded ? 0 : (r.executed ? 1 : 2)
              return rank(a) - rank(b)
            })
            const gaps = av.capability_gaps ?? []
            const missing = gaps.filter((g) => (g.kind ?? 'missing_sensor') === 'missing_sensor')
            const outOfScope = gaps.filter((g) => g.kind === 'out_of_scope')
            const confirmed = av.confirmed ?? rows.filter((r) => r.succeeded).length
            return (
              <>
                <div className="flex gap-3 text-[11px] flex-wrap pb-1 border-b border-border/40">
                  <span className="text-accent">AI asks questions · deterministic translator + gate decide · AI never executes</span>
                  <span className={confirmed > 0 ? 'text-low' : 'text-text-dim'}>{confirmed} confirmed</span>
                  <span className="text-text-dim">{av.executed ?? 0} executed · {rows.length} checked</span>
                  {missing.length > 0 && <span className="text-high">{missing.length} missing sensor(s)</span>}
                  {outOfScope.length > 0 && <span className="text-text-dim">{outOfScope.length} out of scope (intrusive)</span>}
                </div>
                {rows.length === 0 && gaps.length > 0 && (
                  <p className="text-[11px] text-text-dim mt-1">No safe-active checks ran — only non-executable goals were proposed.</p>
                )}
                <div className="space-y-0.5 mt-1">
                  {rows.slice(0, 20).map((r, i) => {
                    const ai = (r.probe ?? '').startsWith('ai_confirm:')
                    const state = r.ai_skipped ? 'aiskip' : (r.succeeded ? 'confirmed' : (!r.gated_allowed ? 'denied' : 'ran'))
                    const glyph = { confirmed: '✓', denied: '⊘', aiskip: '⊙', ran: '·' }[state]
                    const cls = { confirmed: 'text-low', denied: 'text-medium', aiskip: 'text-high', ran: 'text-text-dim' }[state]
                    const ev = (r.evidence ?? '').toLowerCase()
                    const note = r.ai_skipped ? `AI skipped${r.ai_reason ? `: ${r.ai_reason}` : ''}`
                      : r.succeeded ? 'CONFIRMED'
                      : !r.gated_allowed ? `gated: ${(r.denials ?? []).join(', ')}`
                      : ev.includes('no response') ? 'no response (connect/TLS failed)'
                      : ev.includes('no marker') ? 'no marker'
                      : 'no confirmation'
                    return (
                      <div key={i} className="flex items-center gap-2 text-[11px] flex-wrap">
                        <span className={cls}>{glyph}</span>
                        <span className="text-text-bright font-mono text-[10px] break-all">{r.confirms || r.probe}</span>
                        {ai && <span className="text-[10px] text-accent" title="Probe designed by the AI (beyond the fixed sensor suite)">AI-designed</span>}
                        <span className={`text-[10px] ${cls}`}>{note}</span>
                        {r.evidence && !r.ai_skipped && !ev.includes('no response') && (
                          <span className="text-[10px] text-text-dim truncate max-w-[240px]">{r.evidence}</span>
                        )}
                      </div>
                    )
                  })}
                </div>
                {missing.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-border/40">
                    <p className="text-[10px] text-high uppercase tracking-wide mb-1">
                      Missing sensors — no approved read-only observation yet
                    </p>
                    {missing.slice(0, 10).map((g, i) => (
                      <div key={i} className="flex items-center gap-2 text-[11px]">
                        <span className="text-high">✗</span>
                        <span className="text-text-bright font-mono text-[10px] break-all">{g.goal}</span>
                        <span className="text-[10px] text-text-dim">{g.reason}</span>
                      </div>
                    ))}
                  </div>
                )}
                {outOfScope.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-border/40">
                    <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">
                      Out of scope — needs intrusive testing (deliberately not run)
                    </p>
                    {outOfScope.slice(0, 10).map((g, i) => (
                      <div key={i} className="flex items-center gap-2 text-[11px]">
                        <span className="text-text-dim">⊘</span>
                        <span className="text-text-bright font-mono text-[10px] break-all">{g.goal}</span>
                        <span className="text-[10px] text-text-dim">{g.reason}</span>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )
          })()}
        </Panel>
      )}

      {/* ── Investigation Changes (Phase 7 — since last scan) ── */}
      {inView('data') && s.change?.delta && (
        ((s.change.delta.added?.length ?? 0) + (s.change.delta.removed?.length ?? 0) +
         (s.change.delta.changed?.length ?? 0)) > 0
      ) && (
        <Panel title="Investigation Changes (since last scan)" collapsible defaultOpen={false}>
          {s.change!.report && <p className="text-text-bright text-[11px] mb-1">{s.change!.report}</p>}
          {(s.change!.delta!.added ?? []).slice(0, 10).map((d, i) => (
            <p key={`a${i}`} className="text-low text-[11px]">+ {str(d.type) || 'added'} {str(d.node_id ?? d.key ?? d.summary)}</p>
          ))}
          {(s.change!.delta!.changed ?? []).slice(0, 10).map((d, i) => (
            <p key={`c${i}`} className="text-medium text-[11px]">~ {str(d.type) || 'changed'} {str(d.node_id ?? d.key ?? d.summary)}</p>
          ))}
          {(s.change!.delta!.removed ?? []).slice(0, 10).map((d, i) => (
            <p key={`r${i}`} className="text-text-dim text-[11px]">- {str(d.type) || 'removed'} {str(d.node_id ?? d.key ?? d.summary)}</p>
          ))}
          {(s.change!.seed?.objectives?.length ?? 0) > 0 && (
            <p className="text-[10px] text-accent mt-1">
              → re-investigation seeded: {s.change!.seed!.objectives!.join(', ')}
            </p>
          )}
        </Panel>
      )}

      {/* ── Change since last scan ── (has_changes is a Python @property dropped by
            asdict, so detect changes from the arrays directly) ── */}
      {inView('data') && s.scanDiff && (
        (s.scanDiff.ports_added as unknown[] | undefined)?.length ||
        (s.scanDiff.ports_removed as unknown[] | undefined)?.length ||
        (s.scanDiff.version_changes as unknown[] | undefined)?.length ||
        (s.scanDiff.cves_added as unknown[] | undefined)?.length
      ) && (
        <Panel title="Changes Since Last Scan" collapsible defaultOpen={false}>
          {arr((s.scanDiff as Record<string, unknown>).cves_added).map((c, i) => (
            <p key={`ca${i}`} className="text-critical">
              + New vulnerability on port {str(c.port)}
              {c.cve ? <span className="text-text-dim font-mono text-[11px]"> (related {str(c.cve)})</span> : null}
            </p>
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
      {inView('data') && s.exploitability && arr(s.exploitability.attributes).length > 0 && (
        <Panel title="Service Exploitability (Preconditions)" collapsible defaultOpen={false}>
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
      {inView('data') && s.authenticated && Boolean(s.authenticated.success) && (
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
      {inView('data') && s.webFingerprint && (
        <Panel title="Web Application Fingerprint" collapsible defaultOpen={false}>
          <KV k="Title" v={str(s.webFingerprint.title)} />
          <KV k="Generator" v={str(s.webFingerprint.generator)} />
          {s.webFingerprint.is_spa === true && (
            <KV k="Architecture" v={<span className="text-text-dim">Client-routed SPA — path checks content-validated (no /.git·/.env false positives)</span>} />
          )}
          <KV k="Favicon hash" v={s.webFingerprint.favicon_mmh3 != null ? str(s.webFingerprint.favicon_mmh3) : ''} />
          <KV k="Versions" v={(s.webFingerprint.version_markers as string[] | undefined ?? []).join(', ')} />
          <KV k="Exposed files" v={<span className="text-high">{(s.webFingerprint.exposed_files as string[] | undefined ?? []).join(', ')}</span>} />
          <KV k="JS endpoints" v={(s.webFingerprint.js_endpoints as string[] | undefined ?? []).slice(0, 8).join(', ')} />
          {(s.webFingerprint.js_secrets as string[] | undefined ?? []).length > 0 && (
            <KV k="JS secrets" v={<span className="text-critical">{(s.webFingerprint.js_secrets as string[]).join(', ')}</span>} />
          )}
          {/* Third-party SaaS backends (the modern-web attack surface), severity-rated. */}
          {(s.webFingerprint.saas as SaaSHit[] | undefined ?? []).length > 0 && (
            <div className="pt-2 mt-1 border-t border-border/40">
              <p className="text-[10px] text-text-dim uppercase tracking-wide mb-1">Third-party backends (SaaS)</p>
              <div className="space-y-1">
                {(s.webFingerprint.saas as SaaSHit[]).map((h, i) => {
                  const sev = (h.severity ?? 'INFO').toUpperCase()
                  const cls = sev === 'CRITICAL' ? 'text-critical' : sev === 'HIGH' ? 'text-high'
                    : sev === 'MEDIUM' ? 'text-medium' : sev === 'LOW' ? 'text-low' : 'text-text-dim'
                  return (
                    <div key={i} className="text-[11px]">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[9px] font-bold px-1 py-0.5 rounded border uppercase ${cls}`}>{sev}</span>
                        <span className="text-text-bright font-medium">{h.service}</span>
                        {h.category && <span className="text-text-dim text-[10px]">{h.category}</span>}
                        <span className="text-text-dim font-mono text-[10px] break-all">{h.evidence}</span>
                      </div>
                      {h.detail && <p className={`text-[10px] mt-0.5 ${sev === 'INFO' || sev === 'LOW' ? 'text-text-dim' : cls}`}>{h.detail}</p>}
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </Panel>
      )}

      {/* ── Topology ── */}
      {inView('data') && s.topology && (
        <Panel title="Network Topology" collapsible defaultOpen={false}>
          <KV k="Reverse DNS" v={str(s.topology.ptr)} />
          <KV k="ASN" v={[s.topology.asn, s.topology.asn_org, s.topology.country].filter(Boolean).map(str).join(' · ')} />
          <KV k="IPv6" v={(s.topology.ipv6 as string[] | undefined ?? []).slice(0, 3).join(', ')} />
          <KV k="Hops" v={s.topology.hop_count != null ? str(s.topology.hop_count) : ''} />
        </Panel>
      )}

      {/* ── TLS summary ── */}
      {inView('data') && s.tls && arr(s.tls.results).length > 0 && (
        <Panel title="TLS / Certificate" collapsible defaultOpen={false}>
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
