import { describe, it, expect } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import ScanSections from './ScanSections'
import type { ScanSections as ScanSectionsT } from '../api/scan'

/**
 * GUI contract tests for the scan result panels. These assert that the shapes emitted by the
 * Python backend (build_json_report / extractSections) render into the analyst-facing UI —
 * the same data contract the render-verification harness exercised, now pinned as a test.
 */

const investigations: ScanSectionsT = {
  investigations: [
    {
      question: 'Can CVE-2021-31166 be exploited?',
      subject: 'CVE-2021-31166 — iis 10.0: IIS HTTP.sys UAF RCE',
      kind: 'exploitability',
      conclusion: 'LIKELY NOT EXPLOITABLE',
      confidence: 0.65,
      gathered: 2,
      total_evidence: 4,
      evidence: [
        { name: 'CVE matched (CVE-2021-31166)', satisfied: true },
        { name: 'version_check_vulnerable_range', satisfied: false },
        { name: 'reachable_endpoint', satisfied: true },
        { name: 'mitigation_present', satisfied: false },
      ],
    },
    {
      question: 'What technology is running on ex.com:80?',
      subject: 'ex.com:80',
      kind: 'identification',
      conclusion: 'CONFIRMED: iis',
      confidence: 0.92,
      gathered: 1,
      total_evidence: 1,
      evidence: [{ name: 'identify_framework', satisfied: true }],
    },
    {
      question: 'Is cache poisoning possible?',
      subject: 'cache_poisoning',
      kind: 'novel',
      conclusion: 'REFUTED',
      confidence: 0.6,
      gathered: 1,
      total_evidence: 1,
      evidence: [{ name: 'investigate cache_poisoning', satisfied: true }],
    },
  ],
} as ScanSectionsT

describe('ScanSections — Investigations panel', () => {
  it('renders one card per investigation with its question and conclusion', () => {
    render(<ScanSections s={investigations} />)
    expect(screen.getByText('Vulnerability detail')).toBeInTheDocument()
    expect(screen.getByText('Can CVE-2021-31166 be exploited?')).toBeInTheDocument()
    expect(screen.getByText('LIKELY NOT EXPLOITABLE')).toBeInTheDocument()
    expect(screen.getByText('What technology is running on ex.com:80?')).toBeInTheDocument()
    expect(screen.getByText('CONFIRMED: iis')).toBeInTheDocument()
    expect(screen.getByText('Is cache poisoning possible?')).toBeInTheDocument()
    expect(screen.getByText('REFUTED')).toBeInTheDocument()
  })

  it('shows confidence and evidence gathered/total for a card', () => {
    render(<ScanSections s={investigations} />)
    // "confidence 0.65" and "evidence 2/4" each render within a single node.
    expect(screen.getByText(/confidence 0\.65/)).toBeInTheDocument()
    const card = screen.getByText('Can CVE-2021-31166 be exploited?').closest('div')!.parentElement as HTMLElement
    expect(within(card).getByText(/evidence/)).toHaveTextContent('2')
    expect(within(card).getByText(/evidence/)).toHaveTextContent('4')
  })

  it('renders the evidence checklist with satisfied (✓) and unsatisfied (○) markers', () => {
    render(<ScanSections s={investigations} />)
    const satisfied = screen.getByText('reachable_endpoint')
    const unsatisfied = screen.getByText('version_check_vulnerable_range')
    // The marker sits in the same list item as the evidence name.
    expect(satisfied.closest('li')).toHaveTextContent('✓')
    expect(unsatisfied.closest('li')).toHaveTextContent('○')
  })

  it('groups refute checks under the exploitability card (not as separate cards)', () => {
    render(<ScanSections s={investigations} />)
    const card = screen.getByText('Can CVE-2021-31166 be exploited?').closest('div')!
    // the container ancestor should hold all four evidence checks
    const region = card.parentElement as HTMLElement
    expect(within(region).getByText('version_check_vulnerable_range')).toBeInTheDocument()
    expect(within(region).getByText('reachable_endpoint')).toBeInTheDocument()
    expect(within(region).getByText('mitigation_present')).toBeInTheDocument()
  })

  it('does not render the Investigations panel when there are none', () => {
    render(<ScanSections s={{} as ScanSectionsT} />)
    expect(screen.queryByText('Investigations')).not.toBeInTheDocument()
  })

  it('marks an AI-adjudicated card with an AI badge and shows the rationale', () => {
    const s: ScanSectionsT = {
      investigations: [{
        question: 'Can CVE-2023-38408 be exploited?',
        subject: 'CVE-2023-38408', kind: 'exploitability',
        conclusion: 'NOT EXPLOITABLE', confidence: 0.65, gathered: 1, total_evidence: 2,
        adjudicated_by_ai: true, rationale: 'Ubuntu backports the fix without changing the banner',
        evidence: [{ name: 'CVE matched from version banner (CVE-2023-38408)', satisfied: true }],
      }],
    } as ScanSectionsT
    render(<ScanSections s={s} />)
    // the "AI" badge is identified by its title (the intro copy also mentions "AI")
    expect(screen.getByTitle(/Resolved by the AI/)).toHaveTextContent('AI')
    expect(screen.getByText(/Ubuntu backports the fix/)).toBeInTheDocument()
    expect(screen.getByText('NOT EXPLOITABLE')).toBeInTheDocument()
  })
})

const reasoning: ScanSectionsT = {
  reasoning: {
    reasoning_enabled: true,
    investigation: {
      persona: 'analyst',
      objectives: [
        { name: 'identify_framework:ex.com:80', satisfied: true, priority: 0.9 },
        { name: 'verify:CVE-2021-31166', satisfied: false, priority: 0.5,
          source: { generated_by: 'ai_hypothesis_generator' } },
      ],
      hypotheses: [
        { label: 'framework_of:ex.com:80', status: 'confirmed', likelihoods: { iis: 0.8, nginx: 0.2 } },
      ],
      contradictions: [{ subject: 'ex.com:80', reason: 'apache header vs asp.net cookie' }],
    },
    execution: {
      execution_history: [{ step: 'fingerprint', gained: true, rationale: 'server header read' }],
      probe_history: [{}, {}],
      investigation_plans: [
        { objective: 'verify:CVE-2021-31166', goal_reachable: true, max_risk_tier: 'safe_active',
          steps: [{ action_id: 'http_get' }, { action_id: 'match_marker' }] },
      ],
    },
    world: {
      graph: { nodes: [{ id: 'n1', kind: 'service', key: 'ex.com:80', label: 'http', observations: [
        { kind: 'tech', evidence: 'Server: Microsoft-IIS/10.0', source: 'headers' },
      ] }] },
      beliefs: { n1: 0.85 },
    },
  },
} as ScanSectionsT

describe('ScanSections — Reasoning Engine panel', () => {
  it('renders only when reasoning_enabled is true', () => {
    render(<ScanSections s={{ reasoning: { reasoning_enabled: false } } as ScanSectionsT} />)
    expect(screen.queryByText('Reasoning Engine')).not.toBeInTheDocument()
  })

  it('shows objectives with satisfied count and AI-provenance tag', () => {
    render(<ScanSections s={reasoning} />)
    expect(screen.getByText('Reasoning Engine')).toBeInTheDocument()
    expect(screen.getByText('identify_framework:ex.com:80')).toBeInTheDocument()
    // appears both as an objective row and as the investigation-plan objective
    expect(screen.getAllByText('verify:CVE-2021-31166').length).toBeGreaterThan(0)
    // AI-seeded objective surfaces its generator
    expect(screen.getByText('ai_hypothesis_generator')).toBeInTheDocument()
  })

  it('shows the leading hypothesis candidate with its posterior and status', () => {
    render(<ScanSections s={reasoning} />)
    expect(screen.getByText('framework_of:ex.com:80')).toBeInTheDocument()
    expect(screen.getByText('iis 80%')).toBeInTheDocument()
    expect(screen.getByText('confirmed')).toBeInTheDocument()
  })

  it('renders investigation plans, contradictions and the evidence graph', () => {
    render(<ScanSections s={reasoning} />)
    expect(screen.getByText('✓ reachable')).toBeInTheDocument()
    expect(screen.getByText('http_get → match_marker')).toBeInTheDocument()
    expect(screen.getByText(/apache header vs asp\.net cookie/)).toBeInTheDocument()
    expect(screen.getByText(/Microsoft-IIS\/10\.0/)).toBeInTheDocument()
  })
})

const aiReplay: ScanSectionsT = {
  reasoning: {
    reasoning_enabled: true,
    execution: {
      ai_transcript: {
        summary: { proposed: 4, accepted: 3, confirmed: 1, refuted: 1 },
        entries: [
          { agent: 'hypothesis_generator', summary: 'framework is IIS', accepted: true,
            outcome: 'confirmed', uncertainty: 'likely', rationale: 'server header' },
          { agent: 'counterfactual_reasoner', summary: 'cache poisoning', accepted: true,
            outcome: 'refuted', uncertainty: 'possible' },
          { agent: 'hypothesis_generator', summary: 'fabricated CVE', accepted: false,
            stage_failed: 'semantic' },
        ],
      },
    },
  },
} as ScanSectionsT

describe('ScanSections — AI Reasoning Replay panel', () => {
  it('renders only when the transcript has entries', () => {
    render(<ScanSections s={{ reasoning: { reasoning_enabled: true, execution: { ai_transcript: { entries: [] } } } } as ScanSectionsT} />)
    expect(screen.queryByText('AI Reasoning Replay')).not.toBeInTheDocument()
  })

  it('shows the proposed/accepted/confirmed/refuted rollup', () => {
    render(<ScanSections s={aiReplay} />)
    expect(screen.getByText('AI Reasoning Replay')).toBeInTheDocument()
    expect(screen.getByText('4 proposed · 3 accepted')).toBeInTheDocument()
    expect(screen.getByText('1 confirmed')).toBeInTheDocument()
    expect(screen.getByText('1 refuted')).toBeInTheDocument()
  })

  it('shows accepted entries with their outcome and rejected entries with the failing stage', () => {
    render(<ScanSections s={aiReplay} />)
    expect(screen.getByText('framework is IIS')).toBeInTheDocument()
    expect(screen.getByText('confirmed')).toBeInTheDocument()
    expect(screen.getByText('refuted')).toBeInTheDocument()
    expect(screen.getByText('fabricated CVE')).toBeInTheDocument()
    expect(screen.getByText('rejected @ semantic')).toBeInTheDocument()
  })
})

const activeValidation: ScanSectionsT = {
  activeValidation: {
    confirmed: 1,
    executed: 3,
    results: [
      { probe: 'confirm_tech:express', confirms: 'express', gated_allowed: true, executed: true,
        succeeded: true, evidence: 'socket.io handshake' },
      { probe: 'ai_confirm:git_exposure', confirms: 'git_exposure', gated_allowed: true, executed: true,
        succeeded: false, evidence: 'no marker at /.git/config' },
      { probe: 'confirm_tech:intrusive_xyz', confirms: 'intrusive_xyz', gated_allowed: false,
        executed: false, succeeded: false, denials: ['risk exceeds ceiling'] },
    ],
    capability_gaps: [
      { goal: 'mystery_sensor', reason: 'no approved observation strategy', kind: 'missing_sensor' },
      { goal: 'request_smuggling_behavior', reason: 'requires intrusive desync test; outside safe_active ceiling',
        kind: 'out_of_scope' },
    ],
  },
} as ScanSectionsT

describe('ScanSections — Active Validation panel', () => {
  it('renders when there are results', () => {
    render(<ScanSections s={activeValidation} />)
    expect(screen.getByText('Active Validation')).toBeInTheDocument()
    expect(screen.getByText('1 confirmed')).toBeInTheDocument()
    expect(screen.getByText('3 executed · 3 checked')).toBeInTheDocument()
  })

  it('marks a confirmed probe, an AI-designed probe, and a gate-denied probe distinctly', () => {
    render(<ScanSections s={activeValidation} />)
    // confirmed
    expect(screen.getByText('express')).toBeInTheDocument()
    expect(screen.getByText('CONFIRMED')).toBeInTheDocument()
    // AI-designed tag on the ai_confirm: probe
    expect(screen.getByText('AI-designed')).toBeInTheDocument()
    // gate denial surfaces the reason
    expect(screen.getByText(/gated: risk exceeds ceiling/)).toBeInTheDocument()
  })

  it('splits missing sensors from out-of-scope intrusive goals', () => {
    render(<ScanSections s={activeValidation} />)
    expect(screen.getByText('1 missing sensor(s)')).toBeInTheDocument()
    expect(screen.getByText('1 out of scope (intrusive)')).toBeInTheDocument()
    expect(screen.getByText('mystery_sensor')).toBeInTheDocument()
    expect(screen.getByText('request_smuggling_behavior')).toBeInTheDocument()
    expect(screen.getByText(/Missing sensors — no approved/i)).toBeInTheDocument()
    expect(screen.getByText(/Out of scope — needs intrusive testing/i)).toBeInTheDocument()
  })

  it('does not render the panel when there is nothing to validate', () => {
    render(<ScanSections s={{} as ScanSectionsT} />)
    expect(screen.queryByText('Active Validation')).not.toBeInTheDocument()
  })
})

describe('ScanSections — Vulnerabilities (triage)', () => {
  it('leads with vulnerability titles and a priority badge, tucking catalog leads into a disclosure', () => {
    const s = {
      triage: {
        attention: [{ cve: 'CVE-2021-44228', title: 'Remote code execution via JNDI lookup',
                      cvss: 10, kev: true, priority: 'P1', bucket: 'attention',
                      service: 'http', port: 8080, rationale: 'CISA KEV — actively exploited in the wild' }],
        noise: [{ cve: 'CVE-2016-3115', title: 'OpenSSH privilege issue', priority: 'P5', bucket: 'noise',
                  rationale: 'version-match only, no corroborating signal' }],
        counts: { attention: 1, noise: 1, kev: 1, total: 2 },
      },
    } as ScanSectionsT
    render(<ScanSections s={s} />)
    expect(screen.getByText('Vulnerabilities')).toBeInTheDocument()
    // Vulnerability title is primary
    expect(screen.getByText('Remote code execution via JNDI lookup')).toBeInTheDocument()
    // CVE is supporting context (may be split across nodes)
    expect(screen.getByText('Related:')).toBeInTheDocument()
    expect(screen.getByText('CVE-2021-44228')).toBeInTheDocument()
    expect(screen.getByText('P1')).toBeInTheDocument()
    expect(screen.getByText('KEV')).toBeInTheDocument()
    // catalog leads are behind the disclosure summary
    expect(screen.getByText(/catalog lead\(s\) filtered/)).toBeInTheDocument()
  })

  it('surfaces a web/SaaS finding in the hero with its title and a SaaS tag', () => {
    const s = {
      triage: {
        attention: [{ kind: 'web', title: 'Supabase: x.supabase.co', service: 'Supabase',
                      priority: 'P1', bucket: 'attention', rationale: 'service_role key leaked — bypasses RLS' }],
        noise: [], counts: { attention: 1, noise: 0, kev: 0, total: 1 },
      },
    } as ScanSectionsT
    render(<ScanSections s={s} />)
    expect(screen.getByText('Supabase: x.supabase.co')).toBeInTheDocument()
    expect(screen.getByText('SaaS')).toBeInTheDocument()
    expect(screen.getByText(/bypasses RLS/)).toBeInTheDocument()
  })

  it('when nothing is high-priority, reassures instead of alarming', () => {
    const s = {
      triage: { attention: [], noise: [{ cve: 'CVE-X', priority: 'P5', bucket: 'noise', rationale: 'low signal' }],
                counts: { attention: 0, noise: 1, kev: 0, total: 1 } },
    } as ScanSectionsT
    render(<ScanSections s={s} />)
    expect(screen.getByText(/No verified high-priority vulnerabilities/)).toBeInTheDocument()
  })

  it('renders no Top Findings panel without triage', () => {
    render(<ScanSections s={{} as ScanSectionsT} />)
    expect(screen.queryByText('Top Findings')).not.toBeInTheDocument()
  })
})

describe('ScanSections — Architecture Summary', () => {
  it('is structure-first: components + confidence + execution model + surfaces, narrative demoted', () => {
    const s = {
      architecture: {
        narrative: 'This application is a React SPA hosted on Vercel. Authentication is provided by Clerk.',
        stack_kind: 'serverless-spa', execution_model: 'Serverless',
        components: [
          { role: 'frontend', name: 'React SPA', evidence: 'bundle', confidence: 95 },
          { role: 'auth', name: 'Clerk', evidence: 'bundle', confidence: 96 },
          { role: 'backend', name: 'Supabase', evidence: 'bundle', confidence: 96 },
        ],
        attack_surfaces: ['client-side bundle (source is public)', 'authentication flows'],
      },
    } as ScanSectionsT
    render(<ScanSections s={s} />)
    expect(screen.getByText('Architecture Summary')).toBeInTheDocument()
    expect(screen.getByText('React SPA')).toBeInTheDocument()
    expect(screen.getByText('Clerk')).toBeInTheDocument()
    expect(screen.getByText('95%')).toBeInTheDocument()               // deterministic confidence (React SPA)
    expect(screen.getAllByText('96%').length).toBeGreaterThan(0)      // Clerk + Supabase
    expect(screen.getByText('Serverless')).toBeInTheDocument()        // execution model row
    expect(screen.getByText('authentication flows')).toBeInTheDocument()
    // narrative is present but demoted into a collapsible <details>
    expect(screen.getByText(/React SPA hosted on Vercel/)).toBeInTheDocument()
    expect(screen.getByText('Narrative')).toBeInTheDocument()
  })

  it('renders nothing without an architecture narrative', () => {
    render(<ScanSections s={{} as ScanSectionsT} />)
    expect(screen.queryByText('Architecture Summary')).not.toBeInTheDocument()
  })
})

describe('ScanSections — AI Investigation Plan', () => {
  it('renders grounded, numbered investigation objectives with their component + reason', () => {
    const s = {
      investigationPlan: [
        { title: 'Verify Clerk configuration', reason: 'Authentication is externally exposed', component: 'Clerk', priority: 1 },
        { title: 'Enumerate Supabase REST endpoints', reason: 'Backend identified', component: 'Supabase', priority: 2 },
      ],
    } as ScanSectionsT
    render(<ScanSections s={s} />)
    expect(screen.getByText('Investigation Plan')).toBeInTheDocument()
    expect(screen.getByText('Verify Clerk configuration')).toBeInTheDocument()
    expect(screen.getByText('Authentication is externally exposed')).toBeInTheDocument()
    expect(screen.getByText('Clerk')).toBeInTheDocument()
  })

  it('renders no plan panel without AI investigation objectives', () => {
    render(<ScanSections s={{} as ScanSectionsT} />)
    expect(screen.queryByText('Investigation Plan')).not.toBeInTheDocument()
  })
})

describe('ScanSections — smoke', () => {
  it('renders nothing catastrophic for an empty scan', () => {
    const { container } = render(<ScanSections s={{} as ScanSectionsT} />)
    expect(container).toBeInTheDocument()
  })
})

describe('ScanSections — tab views', () => {
  const s = {
    triage: { attention: [{ cve: 'CVE-2021-1', cvss: 9, priority: 'P1', bucket: 'attention', rationale: 'risky' }],
              noise: [], counts: { attention: 1, noise: 0, kev: 0, total: 1 } },
    investigations: [{ question: 'Can CVE-2021-1 be exploited?', conclusion: 'EXPLOITABLE',
                       confidence: 0.9, gathered: 1, total_evidence: 1, evidence: [] }],
    tls: { results: [{ port: 443, grade: 'A', protocols_supported: ['TLSv1.3'], protocols_deprecated: [], cert: {} }] },
    ai: { markdown: '## Executive Summary\nOverall this host is risky.\n\n## Findings\n### 1. Thing `[HIGH]` `[Confirmed]`\n- **What:** detail here',
          provider: 'ollama', model: 'gemma' },
  } as unknown as ScanSectionsT

  it('executive view: Vulnerabilities + Executive Summary only', () => {
    render(<ScanSections s={s} view="executive" />)
    expect(screen.getByText('Vulnerabilities')).toBeInTheDocument()
    expect(screen.getByText(/Overall this host is risky/)).toBeInTheDocument()
    expect(screen.queryByText('TLS / Certificate')).not.toBeInTheDocument()
    expect(screen.queryByText('Vulnerability detail')).not.toBeInTheDocument()
    expect(screen.queryByText(/detail here/)).not.toBeInTheDocument()      // technical content hidden
  })

  it('technical view: detailed AI sections + Vulnerability detail, not the exec/data panels', () => {
    render(<ScanSections s={s} view="technical" />)
    expect(screen.getByText(/Technical Analysis/)).toBeInTheDocument()
    expect(screen.getByText(/detail here/)).toBeInTheDocument()
    expect(screen.getByText('Vulnerability detail')).toBeInTheDocument()
    expect(screen.queryByText('Vulnerabilities')).not.toBeInTheDocument()
    expect(screen.queryByText(/Overall this host is risky/)).not.toBeInTheDocument()
  })

  it('data view: evidence (TLS) only, no AI summary', () => {
    render(<ScanSections s={s} view="data" />)
    expect(screen.getByText('TLS / Certificate')).toBeInTheDocument()
    expect(screen.queryByText('Vulnerabilities')).not.toBeInTheDocument()
    expect(screen.queryByText(/Overall this host is risky/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Technical Analysis/)).not.toBeInTheDocument()
  })
})
