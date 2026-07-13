# NetLogic → HackerOne-grade accuracy plan

**Goal:** Findings good enough that a skilled hunter could open HackerOne reports
with confidence — reproducible steps, correct attribution, no LAN false positives,
honest severity, and no invented exploitability.

This is product quality for *authorized* assessments (customer scope / bug bounty
programs you are enrolled in). It is not a guide to attack systems without permission.

---

## 1. What “HackerOne-grade” means for a scanner

| Bar | Meaning for NetLogic |
|-----|----------------------|
| **Reproducible** | Every confirmed finding has a concrete request/response or observation id an analyst can re-run |
| **Attributed** | Evidence is from the *in-scope asset*, not the scanner’s LAN, CDN edge brand confusion, or shared checklist noise |
| **Severity-honest** | CRITICAL only with impact + reachability; inventory/tech is INFO |
| **No free RCE** | Banner CVE ≠ EXPLOITABLE; timeout ≠ always crash; local privesc ≠ remote |
| **Actionable** | Specific fix or verification command, not “update software” |
| **Scope-clean** | Only hosts/ports in engagement scope; no multi-host thrash off-program |

HackerOne rejects: duplicates, out-of-scope, N/A (theoretical), and “scanner said so.”
Our pipeline must fail **closed** (UNVERIFIED) rather than fail **loud** (false CRITICAL).

---

## 2. Current architecture (money path)

```
Baseline sensors (ports, banners, TLS, DNS, headers, stack)
        ↓
Reasoning objectives + exploitability hypotheses (version leads)
        ↓
AI Investigation Agent (tools: http, ssdp, crash_probe*, dir_enum, …)
        ↓
Agent findings (confirmed only with observation refs)
        ↓
Fusion gate (version-only discarded; agent probe_confirmed → PINNED)
        ↓
AI summary (must consume agent proof + pinned subjects)
        ↓
Report / investigations UI
```

\*crash_probe is opt-in only.

### Recently fixed (this iteration)

1. **UDP/SSDP source scoping** — reject RFC1918 replies when scanning public targets  
2. **Agent finding normalize/dedup** — one `ssdp_exposed`, one `tech_cloudflare`  
3. **Per-CVE investigation evidence** — no global SSH checklist on Apache cards  
4. **Adjudicator policy** — no free “Ubuntu backports” → `ruled_out`  
5. **Agent→fusion pin** — tool-confirmed subjects outrank version discard  

---

## 3. Accuracy gaps still between us and bounty-grade

### P0 — blocks trust / money

| Gap | Failure mode | Fix |
|-----|--------------|-----|
| Weak crash_probe signal | Timeout after control 200 can be WAF/path, not BSOD | Dual control, multi-shot, require connection drop + control still up later; label as *signal* not *RCE* |
| Open redirect quality | Engine CWE-601 may flag benign param bounce | Require external absolute URL, no same-site bounce; store full request/response |
| WAF/challenge sites | Vercel/CF challenge → empty web surface | `browser_get` budget + explicit “blocked by challenge” finding class (not empty report) |
| Agent thrash | 24 steps re-asserting same fact | Stop gates on “no new subjects”; force tool diversity |
| Nuclei noise | Template fire ≠ exploit | Map nuclei → Signal with reliability tiers; never pin without corroboration |

### P1 — report quality

| Gap | Fix |
|-----|-----|
| PoC quality varies by model | Structured PoC field from *engine* (curl reproduction) when probe exists; model only narrates |
| Severity inflation | Map: inventory→info, misconfig→low/med, unauth data leak→high, RCE/SSRF/IDOR with proof→critical |
| Duplicate chains | Canonical chain keys; max 1 chain per (entry, impact) |
| SSDP still in surface leads | Surface builder should drop 1900 unless in-scope reply |

### P2 — bounty workflow

| Gap | Fix |
|-----|-----|
| No program scope file | `--scope` file (domains, wildcards, out-of-scope paths) enforced in ToolRuntime |
| No asset criticality | Tag external login / payment / admin as higher priority for agent depth |
| No report export for H1 | Template: Summary / Steps / Impact / Remediation / Supporting material (HAR-like) |
| No retest diff | `--since-last` already exists — surface “fixed / still open / new” for program retests |

---

## 4. Technical workstreams

### WS-A — Evidence integrity (done + harden)

- [x] UDP/SSDP source IP attribution (`src/ip_scope.py`)
- [x] Scanner `probe_udp_protocol` same gate
- [x] Agent assert_finding canonical ids + SSDP confirm requires in-scope replies
- [ ] Unit/integration: mock LAN gateway reply while scanning public IP → no open 1900
- [ ] Surface builder: port 1900 only if protocol fingerprint was in-scope

### WS-B — Confirmation discipline

- [x] Agent→fusion pin for tool-confirmed non-tech findings
- [x] Adjudicator prompt + weak-`ruled_out` demotion
- [ ] **Confirmation tiers** on every finding:  
  `banner` | `behavior` | `probe` | `exploit_signal` | `manual`  
- [ ] Crash probes emit `exploit_signal` never `confirmed RCE` without secondary evidence  
- [ ] Timing-based enum (OpenSSH CVE-2018-15473) as first-class safe_active tool with stats

### WS-C — Agent quality loop

- [x] Dedup assert_finding  
- [ ] Budget: high-value = new subject or severity upgrade only  
- [ ] Mandatory: for each CVE lead, either probe/tool or leave UNVERIFIED (no adjudicator short-circuit for remote unauth)  
- [ ] Tool result quality scores (status, body entropy, challenge page) fed back into stop  

### WS-D — Report / H1 export

- [x] Per-finding What / Technical / PoC / Remediation prompt contract (Wave B UI)  
- [ ] Engine-generated PoC stubs for probe-confirmed findings  
- [ ] Export `report.hackerone.md` + JSON attachment with raw obs  
- [ ] “Submit readiness” score: has PoC? in-scope? not duplicate? impact clear?

### WS-E — Program safety

- [ ] Scope ACL in ToolRuntime (host + path allow/deny)  
- [ ] Rate limits per host for dir_enum / agent depth  
- [ ] Explicit ban list: no password spray, no write methods (already), no crash without flag  
- [ ] Audit log of every tool call for program review  

---

## 5. Acceptance tests (definition of done)

### False-positive suite

| Case | Must not report |
|------|-----------------|
| Public CDN IP + local UPnP on 192.168.0.1 | SSDP exposed on target |
| IIS 10.0 banner only, crash_probe 200 OK | EXPLOITABLE http.sys |
| Cloudflare `Server:` only | CRITICAL “Cloudflare RCE” |
| OpenSSH version on Ubuntu without timing proof | NOT EXPLOITABLE via “backports” alone |

### True-positive suite (lab only)

| Case | Must report |
|------|-------------|
| Intentionally unpatched lab IIS + crash signal + flag | EXPLOITABLE / critical signal with obs ids |
| Open redirect to external host | CWE-601 with curl PoC |
| Exposed `.env` / key file 200 | CRITICAL with body redacted snippet |
| scanme-style ancient stack | EOL / UNVERIFIED leads, not silent “clean” |

### Regression gates (CI)

- `pytest` for `ip_scope`, agent dedup, fusion pin, adjudicator demotion  
- Cassette corpus: precision ≥ product bar; critical FP = 0 on labeled “noise”  
- Optional nightly: authorized lab targets only  

---

## 6. Severity rubric (align with H1)

| Class | Default | Upgrade when | Downgrade when |
|-------|---------|--------------|----------------|
| Unauth RCE / RCE signal | Critical | Proven crash/control + impact | Signal only → High “needs manual” |
| Unauth SSRF / SQLi / IDOR | High–Critical | Data access proven | Blind only → High |
| Auth bypass | High–Critical | Account takeover path | Partial → High |
| Open redirect | Medium | Token/oauth chain | Open redirect alone |
| Missing headers / soft SPF | Low–Info | Part of phishing chain | Alone |
| Version banner CVE | None (lead) | Probe confirmed | Always until probe |
| Tech inventory | Info | — | Never High |

---

## 7. Rollout sequence

1. **Ship integrity fixes** (this PR): SSDP scope, dedup, evidence, adjudicator policy, fusion pin  
2. **Lab retest** on lwsd / zipenvy / bibliotecapleyades / scanme — expect SSDP FP gone  
3. **WS-B crash + timing tools** — improve real confirmations  
4. **WS-D H1 export** — make payouts operational for hunters on *authorized* programs  
5. **WS-E scope ACL** — required before any multi-customer SaaS “bounty mode”  

---

## 8. Non-goals (explicit)

- Automated HackerOne form submission  
- Weaponized exploit development / reverse shells  
- Scanning assets without written authorization  
- Claiming “confirmed RCE” from a single TCP timeout  

---

## 9. Success metric

Within 30 days of integrity ship:

- **0** SSDP findings on Cloudflare/Vercel pure edges in regression set  
- **0** investigation cards with cross-service evidence contamination  
- Agent confirmed count **≤ unique subjects** (dedup works)  
- Spot-check: 10 random “confirmed” findings manually re-runnable from report PoC  

That is the bar for “could make money on HackerOne”: not more CRITICAL rows — **rows a triage team won’t bounce**.
