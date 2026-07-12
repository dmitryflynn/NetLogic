# NetLogic

**Cloud-Native Attack Surface Mapper & Vulnerability Correlator** — v3.0

NetLogic is a network security platform combining active port scanning, CVE correlation (NVD API + SQLite VDB + offline signatures), SSL/TLS analysis, HTTP security auditing, DNS/email security assessment, subdomain takeover detection, passive OSINT, active vulnerability probing, an AI-driven reasoning engine, cross-host attack chain discovery, and deep probe agent architecture — all accessible from a web dashboard (React SPA), remote agent network, desktop app (Electron), or directly via CLI. The core scan engine is pure Python 3.9+ stdlib with zero third-party dependencies.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/dmitryflynn/netlogic)

---

## Features

| Module | Description |
|---|---|
| **Port Scanner** | TCP connect scan with 43/58 ports, 22 service probes, banner grabbing |
| **CVE Correlator** | NVD API v2.0 + offline SQLite VDB + 192 embedded signatures; EPSS enrichment via FIRST.org |
| **TLS Analyzer** | Protocol versions, weak ciphers, POODLE/BEAST/CRIME/DROWN, cert expiry |
| **HTTP Header Audit** | HSTS, CSP, X-Frame-Options, CORS, cookie flags; 0–100 score |
| **Stack Fingerprint** | CMS, framework, cloud provider, CDN, WAF detection from banner/header/body |
| **DNS Security** | SPF, DKIM, DMARC, DNSSEC, zone transfer, spoofability score |
| **Passive OSINT** | Certificate Transparency logs, DoH DNS, ASN lookup — no direct target contact |
| **Service Prober** | Unauthenticated Redis/Mongo/ES/Docker/K8s/etcd probes, 33 admin paths |
| **Takeover Detector** | CT log subdomain discovery + 25 cloud provider CNAME fingerprints |
| **Nuclei Integration** | Wrapper for 13k+ community templates (CVE, tech, exposure, misconfig) — MIT license |
| **Fusion Pipeline** | Multi-sensor signal gate → deterministic agreement → AI adjudication → attack graph → 6-section report |
| **Web Fingerprint** | Favicon hash (Shodan-compatible mmh3), JS secrets, version markers, exposed files, default lander detection |
| **AI Analysis** | OpenAI / Anthropic / OpenRouter / Ollama / Gemini / Groq / Kimi / Qwen — token-streaming SSE |
| **Reasoning Engine** | Adaptive observe→reason→act loop with EvidenceGraph, hypothesis engine, confidence decay, provenance, scheduler, playbooks, change detection, active validation |
| **Deep Probe** | Per-service agent architecture: ScoutAgent (recon), ProbeAgent (targeted CVE checks), Coordinator, Sandbox |
| **Verifier Engine** | AI-driven CVE re-verification: designs raw-HTTP probe plans from CVE context, executes via stdlib sockets |
| **Multi-Host Orchestration** | Full scan pipeline per host → cross-host context and reachability matrix → attack chain discovery |
| **AI Sensor Directors** | LLM decides which sensors to prioritise based on open ports, tech stack, and CVEs |
| **Authenticated SSH** | Credentialed `ssh` subprocess reads real installed package versions (60+ product mappings) |
| **VDB (Offline CVE DB)** | SQLite database with incremental NVD sync; product-aware version matching with CONFIRMED/POTENTIAL status |
| **Service Enum** | Protocol-level attribute extraction (SSH KEX, SMBv1, RDP NLA, SNMP community, HTTP auth state) |
| **Topology Mapper** | Reverse DNS, IPv6, traceroute, ASN/org/country via ip-api.com |
| **Reachability Prober** | Post-compromise lateral movement matrix from subnet adjacency |
| **Network Prober** | Active subnet sweep (/24 private neighbours) with two-phase discovery (live sweep → full port scan) |
| **Scan Diff** | Change-over-time: diffs current scan against most recent prior JSON report per target |
| **License Management** | Commercial license system with key activation (stub for Stripe/Paddle/Lemon Squeezy) |
| **Per-Org AI Config** | Each org stores its own LLM credentials encrypted at rest via Fernet |
| **OIDC / Clerk** | Human logins via Clerk-issued session JWTs verified against public JWKS with auto-provisioning |
| **PostgreSQL** | Full multi-tenant persistence with auto-applied migrations (scan jobs, org settings, reasoning state, audit) |
| **Fusion Benchmark** | Offline benchmark against recorded HTTP cassettes; precision/recall/critical-recall/FP-reduction metrics |

---

## Deployment Modes

| Mode | Description |
|---|---|
| **CLI** | `netlogic <target>` — zero third-party dependencies, pure Python 3.9+ stdlib. Entry point via `api.cli:main` → `netlogic.py:main()`. |
| **GUI / Local** | `netlogic --gui` — starts FastAPI + React SPA with auto-generated secrets and in-process scan agent. No external agent needed. |
| **SaaS / Web** | FastAPI controller + React dashboard. Scans delegated to registered remote agents. Built-in local agent starts automatically. |
| **Remote Agent** | `netlogic_agent.py` polls controller via agent protocol (heartbeat/task/events/complete), runs stdlib engine on local network. |
| **Desktop** | Electron shell (`electron/main.js`) bundles the Python backend. Built for Windows via NSIS. |

---

## Quick Start

```bash
# CLI — install and run (stdlib only)
pip install -e .
netlogic scanme.nmap.org --full

# Or without installation
python netlogic.py scanme.nmap.org --full

# Web dashboard (local mode) — install API deps, then
pip install -r requirements-api.txt
netlogic --gui
# → Dashboard at http://localhost:8000, auto-generated secrets in ~/.netlogic/secrets.json

# SaaS mode
pip install -r requirements-api.txt
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Docker
docker compose up --build
```

---

## CLI Reference

```
netlogic [target] [flags]
```

The entry point is `api.cli:main` (defined in `pyproject.toml`), which delegates to `netlogic.py:main()`. All scan logic is in `src/`.

### Target specification
| Format | Example | Mode |
|---|---|---|
| Hostname | `example.com` | Single-host scan |
| IPv4 | `10.0.0.5` | Single-host scan |
| CIDR | `192.168.1.0/24` | CIDR sweep (scanner only, no fusion) |
| Comma-separated | `target1,target2` | Multi-host orchestration (cross-host context) |

### Scan scope

```
# Basic scan — 43 common ports + CVE correlation
netlogic example.com

# Full scan — all modules enabled
netlogic example.com --full

# Deep TLS + HTTP header audit
netlogic example.com --tls --headers

# Subdomain takeover detection
netlogic example.com --takeover

# Passive OSINT only
netlogic example.com --osint

# Technology stack + WAF fingerprinting
netlogic example.com --stack

# DNS/email security (SPF, DKIM, DMARC, DNSSEC)
netlogic example.com --dns

# Active service probing (unauthenticated access, default creds, CVE-specific checks)
netlogic 10.0.0.5 --probe

# Everything — all flags combined
netlogic example.com --full --probe
```

### Port selection

```
# Quick — 43 common ports (default)
netlogic example.com --ports quick

# Full — 58 extended ports
netlogic example.com --ports full

# Custom list
netlogic example.com --ports custom=22,80,443,8080,9200
```

### AI analysis

```
# OpenRouter (default)
netlogic example.com --ai --ai-key $KEY

# OpenAI
netlogic example.com --ai --ai-provider openai --ai-key $KEY --ai-model gpt-4o-mini

# Anthropic
netlogic example.com --ai --ai-provider anthropic --ai-key $KEY

# Gemini
netlogic example.com --ai --ai-provider gemini --ai-key $KEY --ai-model gemini-2.0-flash

# Local Ollama
netlogic example.com --ai --ai-provider ollama

# Custom OpenAI-compatible endpoint
netlogic example.com --ai --ai-provider custom --ai-base-url https://... --ai-model model-name
```

### AI providers supported

| Provider | Default model | API style |
|---|---|---|
| `openrouter` | `anthropic/claude-sonnet-4` | OpenAI |
| `openai` | `gpt-4o-mini` | OpenAI |
| `anthropic` | `claude-3-5-sonnet-20241022` | Anthropic Messages |
| `kimi` (Moonshot) | `kimi-k2.6` | OpenAI |
| `qwen` (Alibaba) | `qwen-plus` | OpenAI |
| `groq` | `llama-3.3-70b-versatile` | OpenAI |
| `gemini` (Google) | `gemini-2.0-flash` | OpenAI |
| `ollama` | `llama3` | OpenAI |
| `custom` | user-specified | OpenAI |

### Reasoning engine

```
# Adaptive observe→reason→act loop (deterministic by default; AI-augmented with --ai)
netlogic example.com --reason

# Multi-host world modeling — discovers in-scope neighbours, reasons per host
netlogic example.com --reason --multi-host

# Change detection — diffs against prior saved report
netlogic example.com --since-last

# Active validation — confirms hypotheses with safe non-destructive GETs
netlogic example.com --reason --active-validate

# Deep probe — per-service agent architecture with context isolation
netlogic example.com --deep-probe
```

### Authenticated scanning

```
# SSH key-based — reads real installed package versions
netlogic example.com --ssh-user admin --ssh-key ~/.ssh/id_rsa

# SSH password (requires sshpass)
netlogic example.com --ssh-user admin --ssh-pass SECRET

# Custom SSH port
netlogic example.com --ssh-user admin --ssh-key ~/.ssh/id_rsa --ssh-port 2222
```

### Vulnerability database management

```
# Show offline CVE DB status (freshness, count)
netlogic --vdb-status

# Full sync from NVD
netlogic --vdb-sync

# Partial sync (first N products)
netlogic --vdb-sync 50
```

### Benchmark

```
# Fusion pipeline benchmark against recorded cassettes (oracle mode — perfect AI upper bound)
netlogic --benchmark

# With real AI model
netlogic --benchmark --benchmark-ai

# Export report
netlogic --benchmark --benchmark-export report.md

# Verbose per-subject output
netlogic --benchmark --benchmark-verbose
```

### Output

```
# Report format
netlogic example.com --report terminal     # terminal output (default)
netlogic example.com --report json         # JSON file
netlogic example.com --report html         # HTML report
netlogic example.com --report all          # terminal + JSON + HTML

# Output directory
netlogic example.com --out ./reports

# CVSS threshold
netlogic example.com --min-cvss 7.0

# Colour
netlogic example.com --no-color
```

### NVD cache management

```
netlogic --clear-cache
netlogic --cache-stats
netlogic --preload-cache
netlogic example.com --nvd-key YOUR_NVD_KEY
```

### Misc

```
netlogic --version            # Show version and exit
netlogic --gui                # Start web dashboard
```

---

## Fusion Pipeline

The fusion pipeline is a **sensors → gate → AI adjudication → synthesis** funnel that replaces monolithic AI calls with a precision gate. It lives in `src/fusion/` (12 files).

### Signal schema (`src/fusion/signals.py`)

Evidence-bearing data contract. Every sensor emits `Signal` objects:
- `source`: `probe`/`banner`/`nuclei`/`wappalyzer`/`nvd`/`osv`/`tls`/`dns`
- `kind`: `vuln`/`tech`/`exposure`/`misconfig`/`service`
- `claim`: normalised subject (e.g. `"CVE-2021-44228"`, `"nginx"`)
- `host`, `port`, `service`, `evidence` (capped 600 chars)
- `confidence` (0..1), `reliability` (`high`/`medium`/`low`)
- `kev`, `epss` (0..1), `cvss` (0..10), `exploit_available`, `version_matched`, `probe_confirmed`
- `exposure` dict (reachability, WAF, vantage)
- `observed_data` (raw bytes sent to AI — NOT sensor names or severities to prevent label bias)
- `ai_view()` strips sensor metadata, returns only observed facts

### Gate (`src/fusion/gate.py`)

Deterministic agreement — given `list[Signal]`, groups by subject and returns `list[Verdict]`:

| Condition | Verdict |
|---|---|
| KEV-listed OR probe-confirmed OR critical+exploit/high-EPSS | **Confirmed** (pinned — un-droppable) |
| ≥2 independent sources agree, ≥1 high-reliability | **Confirmed** (unless all are version-matched → gray) |
| Solo low-reliability, low/medium impact, no corroboration | **Discarded** |
| Everything else | **Gray** (costs an AI token) |

### AI Adjudication (`src/fusion/adjudicator.py`)

Only touches the gray band. Safety constraints enforced in code (not prompt):
- High/critical gray items can NEVER be discarded — at worst demoted to `potential`
- Version-only matches capped at `potential` (distros backport without version bumps)
- AI also discovers new findings from full host context
- Fail-soft: AI outage leaves gray band as `potential` — no silent data loss

### Synthesis (`src/fusion/synthesis.py`)

`build_attack_graph(verdicts)` → deterministic reachability graph from CONFIRMED findings.
`full_synthesize(...)` → 6-section AI report:
1. Executive Summary
2. Key Findings (table)
3. Attack Chains (graph-based, LLM narrates real edges)
4. Beyond Known CVEs
5. False Positives & Noise
6. Remediation

### Sensors

| Sensor | File | What it produces |
|---|---|---|
| Engine bridge | `engine_bridge.py` | Converts scan artifacts → Signals from NVD, probes, stack, Nuclei, verifier |
| Wappalyzer | `sensors/wappalyzer.py` | Zero-dependency Wappalyzer-compatible fingerprinting of HTTP responses |
| Nuclei | `sensors/nuclei.py` | Runs YAML templates against responses (subset of Nuclei syntax) |
| Cassette | `cassette.py` | Record/replay from HTTP cassettes (offline benchmark data) |

### Cross-host (`src/fusion/cross_host.py`)

Post-adjudication grouping of verdicts across hosts by shared service+version for multi-hop attack chain narration in synthesis.

### Pipeline Flow

```
Engine artifacts / Cassette data
    ↓
engine_bridge.py / cassette.py     → Signal list
    ↓
gate.py::adjudicate()              → Verdict list (confirmed/discarded/gray)
    ↓
adjudicator.py::run_adjudication() → AI on gray band only
    ↓
synthesis.py::full_synthesize()    → 6-section report + attack graph
```

---

## Reasoning Engine

Located in `src/reasoning/` (~58 files). Multi-phase, safety-gated, observe→reason→act loop. Enabled with `--reason`.

### Core loop (`src/reasoning/director.py` — `ReconDirector.run()`)

1. **Phase 2 Sensor Sweep**: `StrategyManager` selects persona → `Scheduler` picks action → `SensorStep` executes → `EvidenceGraph` folds observations → `ConfidenceEngine` refreshes beliefs
2. **Phase 3 AI Cycle**: Deterministic generators populate objectives/hypotheses → AI agents propose typed `Proposal` envelopes → `AICoordinator` normalises/ranks/verifies → accepted proposals seed state → `Compiler` → `ExecutionPlanner` → `ExecutionKernel` runs probes → `InferenceEngine` resolves
3. **Phase 6c Multi-host**: Cross-host discovery via `CrossHostGraph`, spawns child `HostReasoner` instances
4. **Phase 8 Planning Pass**: `GoalPlanner` produces investigation plans
5. **Continuous**: `ReasoningValidator` integrity audit → `ProvenanceBuilder` records edges → state persisted

### State hierarchy (`src/reasoning/state.py`)

| Layer | Class | What it tracks |
|---|---|---|
| WorldModel | `WorldModel` | EvidenceGraph, observations, beliefs, hosts, technology, reachability |
| InvestigationState | `InvestigationState` | Objectives (DAG), hypotheses, contradictions, dead-ends, current persona |
| ExecutionState | `ExecutionState` | Budget, probe_history, provenance, investigation_plans, AI transcript |
| LearnedPatterns | `LearnedPatterns` | Cross-scan heuristics + playbooks |

### Key components

| Component | File | Description |
|---|---|---|
| EvidenceGraph | `evidence_graph.py` | Deduplicated temporal entity graph (content-addressed observations via SHA-256) |
| Hypothesis engine | `hypothesis.py` | Competing candidates with likelihoods, entropy, information gain, posterior resolution |
| ConfidenceEngine | `confidence.py` | Noisy-OR over distinct sources; version-only capped at 0.60; KEV/probe pinned at 0.97 |
| ProvenanceBuilder | `provenance.py` | Observation→Inference→Hypothesis edges, content-hash addressed |
| Scheduler | `scheduler.py` | Information-gain action selection with explore_reserve (10%) |
| StrategyManager | `strategy.py` | Meta-reasoning: persona selection, explore/exploit mode, plateau detection |
| ActionGate | `action_gate.py` | Defense-in-depth: risk tiers (READ_ONLY < SAFE_ACTIVE < INTRUSIVE < EXPLOIT), core max is SAFE_ACTIVE |
| InferenceEngine | `inference.py` | Deterministic rules from `rules/*.json`, never writes confidence |
| NovelInferenceEngine | `novel_inference.py` | Rules for cache_poisoning, request_smuggling, auth_bypass etc. |
| ExecutionKernel | `execution_kernel.py` | Validates + executes + traces probes (scope → read-only → budget → dedup → depth) |
| Playbook system | `playbooks.py` | YAML playbooks with trigger conditions and intent templates |
| Change detection | `change_detection.py` | Phase 7: diffs immutable observations (not state), produces ScanDelta of DeltaEvents |
| Active validation | `active_validation.py` | Phase 8b: non-destructive SAFE_ACTIVE probes through ActionGate |

### AI subsystem (`src/reasoning/ai/`)

Pipeline: Generate → Normalize → Rank → (MetaReasoner prune) → Verify → Store

| File | Component |
|---|---|
| `coordinator.py` | `AICoordinator` — staged pipeline orchestration |
| `proposals.py` | Typed `Proposal` envelope with kind-specific payload, provenance, economics |
| `normalize.py` | `ProposalNormalizer` — total validation gate |
| `rank.py` | `ProposalRanker` — score = raw_score × prob_correct × reputation_weight |
| `meta_reasoner.py` | Deterministic pruning (loop detection, uncertainty reduction) |
| `verifier.py` | 4-stage: Syntax → Semantic → Evidence → Safety |
| `store.py` | `ProposalStore` — lifecycle ledger |
| `transcript.py` | `InvestigationTranscript` — causal chain recording |
| `evaluation.py` | Cassette-based deterministic evaluation harness |
| `reputation.py` | `AgentReputation` — tracks accept/reject rate per agent |
| `agents/hypothesis_generator.py` | C1 — proposes competing explanations + novel-vuln hypotheses |
| `agents/counterfactual.py` | C11 — proposes refutation objectives |
| `agents/investigation_designer.py` | C2 — designs evidence-gathering plans |

---

## Deep Probe Architecture

Located in `src/deep/` (7 files). Used with `--deep-probe`. Per-service agent architecture for context-isolated probe execution.

| Component | File | Description |
|---|---|---|
| `DeepCoordinator` | `coordinator.py` | Orchestrates full deep pipeline: AI sensor plan → ScoutAgent → per-service ProbeAgent → service enum → Nuclei → verifier → takeover → subnet probe → topology → auth → diff → reachability |
| `ScoutAgent` | `scout_agent.py` | Passive recon: TLS, headers, stack, DNS, OSINT |
| `ProbeAgent` | `probe_agent.py` | Targets one service with isolated CVE/tech context — runs probes + verifier |
| `ExploitChain` | `chain.py` | BFS attack path planning over fusion-confirmed verdicts, PoC generation |
| `Sandbox` | `sandbox.py` | Restricted subprocess for PoC validation (temp dir, timeout, clean-up) |
| `Mission` / `AgentReport` | `models.py` | Data models for agent directives and results |

`DeepCoordinator.run()` flow:
1. Build AI sensor plan (`_build_sensor_plan` via `sensor_director`)
2. Dispatch `ScoutAgent` for passive recon
3. Group findings by service → per-service `ProbeAgent` instances (each with isolated CVE/tech context)
4. Run service enumeration, Nuclei (AI-selected tags), verifier engine, takeover, AI-directed subnet probe, topology, authenticated SSH, scan diff, reachability probing

---

## Verifier Engine

Located in `src/verifier/` (3 files). AI-driven CVE confirmation with targeted probes.

| Component | File | Description |
|---|---|---|
| `run_verifier()` | `engine.py` | Orchestrates: generate plans → execute → construct probe-confirmed Signals |
| `generate_plans_for_cves()` | `planner.py` | Per-CVE (CVSS ≥ 7.0): checks ~20 built-in plans → AI generates raw-HTTP plan (method, path, headers, body, expected status/body) |
| `run_test()` | `runner.py` | Raw TCP/TLS socket execution, manual HTTP/1.0 parsing, expected body pattern matching |

Phase 2 re-verification (`reverify_with_context`) provides full host context to refine failed tests.

---

## AI Sensor Directors

Located in `src/directors/` (4 files). LLM-driven scan parameter selection.

| Director | File | What it decides |
|---|---|---|
| `SensorDirector` | `sensor_director.py` | Which sensors to enable/disable and at what priority, based on open ports + tech stack + CVEs |
| `ReprobeDirector` | `reprobe.py` | Whether potential findings can be resolved with targeted HTTP probes |
| `NucleiSelector` | `nuclei_selector.py` | Which Nuclei template tags to include/exclude (reduces irrelevant runs) |
| `SubnetDirector` | `subnet_director.py` | Which adjacent hosts to probe, which ports, at what depth (skip/quick/standard/deep) |

---

## Multi-Host Orchestration

Located in `src/orchestrator.py`. Triggered by comma-separated targets. Runs `run_scan()` per host, aggregates results, builds cross-host context from combined fusion verdicts. Cross-host groups detect shared services/versions across hosts for multi-hop attack chain narration.

---

## CVE Coverage

### Offline: SQLite VDB (`src/vdb_engine.py`)
- Pre-populated SQLite with CPE→CVE mappings for ~70 enterprise products
- Product-aware matching with CONFIRMED/POTENTIAL status
- KEV and Metasploit flags per vulnerability
- Incremental sync from NVD (`--vdb-sync`)
- Status via `--vdb-status`

### Live: NVD API v2.0 (`src/nvd_lookup.py`)
- Live lookup for uncovered products/versions
- 192 offline signatures for air-gapped environments
- On-disk cache with atomic writes
- NVD API key for higher rate limits (`--nvd-key`)

### Enrichment
- **EPSS** (`src/epss.py`): FIRST.org API in batches of 100 CVE IDs, 24h disk cache at `~/.netlogic/epss_cache.json`, fail-soft to 0.0
- **CISA KEV**: CVEs actively exploited in the wild
- **Public exploit tracking**: Metasploit and PoC markers

---

## Nuclei Integration

`src/external/nuclei_runner.py` wraps the Nuclei binary (MIT license). Optional — degrades gracefully when binary not found. Results feed into fusion pipeline as typed signals (severity labels stripped to prevent LLM bias).

```
# Install Nuclei
scoop install nuclei    # Windows
brew install nuclei     # macOS
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  # Linux
```

---

## Fusion Benchmark

`src/fusion/benchmark.py` — offline measurement against labeled HTTP cassettes (`benchmark/*.json` and `src/fusion/data/`). Metrics:

| Metric | Gate threshold |
|---|---|
| FP reduction | ≥ 80% |
| Critical recall | = 100% |

Two modes:
- **Oracle** (`--benchmark`): perfect-AI upper bound — measures deterministic machinery alone
- **Real model** (`--benchmark --benchmark-ai`): measured with configured LLM

---

## Architecture

```
netlogic/
├── netlogic.py                  ← CLI entry point (argparse, all scan modes)
├── netlogic_agent.py            ← Remote agent runner (stdlib-only, agent protocol)
│
├── src/                         ← Scan engine (zero third-party deps)
│   ├── scanner.py               ← TCP scanner, 22 service probes, banner grabbing
│   ├── engine.py                ← Orchestrator: SensorStep pipeline, all scan modules + fusion
│   ├── orchestrator.py          ← Multi-host: per-host scan → cross-host context
│   ├── ai_analyst.py            ← LLM integration (9 providers, stdlib-only transport)
│   ├── cve_correlator.py        ← CVE matching: NVD + offline sigs
│   ├── nvd_lookup.py            ← NVD API v2.0 client, disk cache, CISA KEV
│   ├── epss.py                  ← EPSS enrichment (FIRST.org, 24h cache)
│   ├── vdb_engine.py            ← SQLite local vulnerability database
│   ├── vdb_syncer.py            ← Incremental VDB sync from NVD
│   ├── service_prober.py        ← Unauthenticated service access, default creds, admin paths
│   ├── vuln_prober.py           ← CVE-specific safe active probes
│   ├── osint.py                 ← DoH, CT logs, ASN lookup
│   ├── tls_analyzer.py          ← SSL/TLS deep analysis
│   ├── header_audit.py          ← HTTP security header audit
│   ├── stack_fingerprint.py     ← CMS, framework, cloud, CDN, WAF detector
│   ├── web_fingerprint.py       ← Favicon mmh3, JS secrets, version files, exposed paths, lander detection
│   ├── dns_security.py          ← SPF, DKIM, DMARC, DNSSEC, zone transfer
│   ├── takeover.py              ← Subdomain takeover (25 provider fingerprints)
│   ├── authenticated.py         ← SSH subprocess: dpkg/rpm/apk parsing, 60+ product mappings
│   ├── topology.py              ← PTR, IPv6, traceroute, ASN/org/country
│   ├── reachability_prober.py   ← Lateral movement matrix from subnet adjacency
│   ├── network_prober.py        ← /24 subnet sweep: live-host → full port scan
│   ├── service_enum.py          ← Protocol attribute extraction (SSH KEX, SMBv1, RDP NLA, SNMP)
│   ├── ssl_utils.py             ← Configurable SSL context management, TLS probe
│   ├── scan_diff.py             ← Change-over-time: diffs against prior JSON report
│   ├── json_bridge.py           ← Streaming JSON events for agent/Electron
│   ├── reporter.py              ← Terminal, JSON, HTML output renderers
│   │
│   ├── fusion/                  ← Precision funnel (12 files)
│   │   ├── signals.py           ← Signal schema
│   │   ├── gate.py              ← Deterministic agreement
│   │   ├── adjudicator.py       ← AI adjudication (gray band only)
│   │   ├── synthesis.py         ← Attack graph + 6-section report
│   │   ├── ai.py                ← CompleteFn/StreamCompleteFn adapter
│   │   ├── engine_bridge.py     ← Artifacts → Signals → verdicts
│   │   ├── benchmark.py         ← Offline benchmark (oracle + real model)
│   │   ├── cassette.py          ← HTTP cassette record/replay
│   │   ├── corpus.py            ← Cassette→case conversion + CLI
│   │   ├── cross_host.py        ← Cross-host verdict correlation
│   │   ├── sensors/nuclei.py    ← Nuclei YAML → Signal conversion
│   │   └── sensors/wappalyzer.py← Wappalyzer fingerprint → Signal
│   │
│   ├── directors/               ← AI sensor directors (4 files)
│   │   ├── sensor_director.py   ← LLM selects which sensors to enable
│   │   ├── reprobe.py           ← LLM designs re-probe plans
│   │   ├── nuclei_selector.py   ← LLM selects Nuclei template tags
│   │   └── subnet_director.py   ← LLM directs subnet probing
│   │
│   ├── verifier/                ← AI CVE verification (3 files)
│   │   ├── engine.py            ← Verifier orchestration
│   │   ├── planner.py           ← Built-in + AI-generated probe plans
│   │   └── runner.py            ← Raw TCP/TLS probe execution
│   │
│   ├── deep/                    ← Deep probe agents (7 files)
│   │   ├── coordinator.py       ← Full deep pipeline orchestrator
│   │   ├── scout_agent.py       ← Passive recon agent
│   │   ├── probe_agent.py       ← Per-service probe agent
│   │   ├── chain.py             ← Exploit chain planning + PoC generation
│   │   ├── sandbox.py           ← Restricted PoC execution
│   │   ├── base_agent.py        ← Abstract base
│   │   └── models.py            ← Mission/AgentReport data models
│   │
│   ├── reasoning/               ← Adaptive reasoning engine (~58 files)
│   │   ├── director.py          ← ReconDirector (main loop)
│   │   ├── state.py             ← WorldModel/InvestigationState/ExecutionState
│   │   ├── hypothesis.py        ← Hypothesis engine (competing candidates)
│   │   ├── evidence_graph.py    ← Temporal entity graph (content-addressed obs)
│   │   ├── confidence.py        ← Noisy-OR belief computation
│   │   ├── provenance.py        ← Observation→Inference→Hypothesis edges
│   │   ├── scheduler.py         ← Information-gain action selection
│   │   ├── strategy.py          ← Meta-reasoning: personas, explore/exploit
│   │   ├── strategies.py        ← Concrete strategy implementations
│   │   ├── action_gate.py       ← Risk-tiered probe authorisation
│   │   ├── change_detection.py  ← Phase 7: observation-level diff
│   │   ├── active_validation.py ← Phase 8b: SAFE_ACTIVE probes
│   │   ├── cross_host.py        ← Cross-host world modeling
│   │   ├── objective.py         ← Objective DAG management
│   │   ├── intent.py            ← Intent model + EvidenceType enum (29 types)
│   │   ├── candidate.py         ← Action candidate with lazy factory
│   │   ├── actions.py           ← Action model with RiskTier + Predicate
│   │   ├── compiler.py          ← Intent → InvestigationGraph
│   │   ├── execution_planner.py ← InvestigationGraph → ProbePlanGraph
│   │   ├── execution_kernel.py  ← Probe execution with validators
│   │   ├── probe_executor.py    ← Read-only probe backends
│   │   ├── primitive_registry.py← Probe primitive catalogue
│   │   ├── generators.py        ← Deterministic objective/hypothesis population
│   │   ├── playbooks.py         ← YAML playbook system
│   │   ├── planning_pass.py     ← GoalPlanner integration
│   │   ├── budget.py            ← Probe budget management
│   │   ├── inference.py         ← Deterministic rule-based inference
│   │   ├── novel_inference.py   ← Novel-vuln hypothesis rules
│   │   ├── investigation_planner.py  ← Goal-directed investigation planning
│   │   ├── investigation_memory.py   ← Strategy attempt memory
│   │   ├── observation_translator.py ← Raw data → structured observations
│   │   ├── observation.py       ← Immutable, content-addressed observation
│   │   ├── reflect.py           ← PlannerFeedback generation
│   │   ├── reasoning_validator.py ← Continuous integrity audit
│   │   ├── builder.py           ← State population from artifacts
│   │   ├── trace.py             ← Execution tracing
│   │   ├── explanation.py       ← Explanation records
│   │   ├── ai/                  ← AI cognitive layer (subsystem)
│   │   ├── packs/               ← Technology pack calibration
│   │   ├── playbooks/           ← YAML playbook templates
│   │   └── rules/               ← JSON inference rules
│   │
│   └── external/nuclei_runner.py ← Nuclei binary wrapper
│
├── api/                         ← FastAPI controller
│   ├── main.py                  ← App factory, lifespan, middleware stack
│   ├── cli.py                   ← Typer -> netlogic.py bridge
│   ├── db.py                    ← PostgreSQL connection + migration runner
│   ├── crypto.py                ← Fernet seal/unseal (AES-128-CBC + HMAC-SHA256)
│   ├── auth/
│   │   ├── api_keys.py          ← Dual-store (memory/PG), SHA-256 hashed
│   │   ├── jwt_handler.py       ← Stdlib-only HS256 JWT
│   │   ├── oidc.py              ← Clerk/IdP OIDC (RS256 + JWKS)
│   │   ├── license.py           ← LicenseManager (stub → real payment API)
│   │   ├── rate_limit.py        ← Sliding-window, IP banning
│   │   ├── provisioning.py      ← Clerk auto-provisioning
│   │   └── dependencies.py      ← require_org FastAPI dependency
│   ├── agents/
│   │   ├── registry.py          ← Agent lifecycle (concurrency-aware, JSON persistence)
│   │   └── local_agent.py       ← Built-in in-process agent
│   ├── jobs/
│   │   ├── manager.py           ← ScanJob lifecycle, capped event deque (10k), SSE, Postgres
│   │   └── executor.py          ← Dispatch (capability/selector, least-loaded, reclaimer)
│   ├── middleware/audit.py      ← X-Request-ID + structured audit + SIEM shipping
│   ├── models/
│   │   ├── scan_request.py      ← Pydantic ScanRequest (ipaddress validation)
│   │   └── agent.py             ← AgentRegistration constraints
│   ├── routes/
│   │   ├── auth.py              ← /v1/auth/*
│   │   ├── jobs.py              ← /v1/jobs/*
│   │   ├── agents.py            ← /v1/agents/*
│   │   ├── health.py            ← /health + /v1/health
│   │   ├── license.py           ← /v1/license/*
│   │   ├── vdb.py               ← /v1/vdb/*
│   │   └── settings.py          ← /v1/settings/*
│   └── storage/
│       ├── json_store.py         ← 10 MB cap, 500 file cap, atomic writes
│       ├── pg_store.py           ← Postgres JSONB upsert
│       └── reasoning_store.py    ← Dual-store for reasoning state
│
├── dashboard/                   ← React SPA (Vite + TypeScript + Tailwind + Clerk)
│   └── src/
│       └── pages/               ← Dashboard, NewScan, ScanDetail, Agents, Targets,
│                                   TargetTimeline, Settings, License, Login, SignUp, Legal
│
├── electron/                    ← Desktop app shell (Electron)
│   ├── main.js                  ← BrowserWindow, sandbox, contextIsolation
│   └── preload.js               ← IPC bridge
│
├── docs/                        ← Design documentation
│   ├── DEPLOY_SAAS.md, saas-auth.md
│   ├── REASONING_ENGINE_DESIGN.md
│   ├── LEGAL_COMPLIANCE.md
│   ├── ENTERPRISE_READINESS.md
│   └── DESIGN_PARTNER_PACK.md
│
├── db/migrations/               ← PostgreSQL schema migrations
├── benchmark/                   ← HTTP cassette recordings for fusion benchmark
└── scripts/                     ← Dev utilities (run_api_dev.py)
```

---

## API Reference

All routes under `/v1/` prefix. Authentication:
- **Machine**: API key → `POST /v1/auth/token` → HS256 JWT (default 1h expiry)
- **Human**: Clerk OIDC session JWT → `require_org` dependency verifies against JWKS

### Auth

```
POST   /v1/auth/token          Exchange API key for JWT          [10/min/IP]
POST   /v1/auth/keys           Create API key (X-Admin-Key)       [admin]
GET    /v1/auth/keys           List keys (masked)                 [admin]
DELETE /v1/auth/keys           Revoke key (body, not URL)         [admin]
```

### Jobs

```
POST   /v1/jobs                Create scan job                    [30/min/org]
GET    /v1/jobs                List recent jobs
GET    /v1/jobs/history/{target}  Scan history for target
GET    /v1/jobs/{id}           Job detail
GET    /v1/jobs/{id}/stream    SSE event stream                   [60/min/org]
GET    /v1/jobs/{id}/export    Export (format=json|md|raw)
POST   /v1/jobs/{id}/explore-beyond  AI deep-dive on finding
POST   /v1/jobs/{id}/cancel    Cancel job
DELETE /v1/jobs/{id}           Remove job
```

### Agents

```
POST   /v1/agents/register               Register agent         [5/hr/IP]
POST   /v1/agents/{id}/heartbeat         Keep-alive             [3/min]
GET    /v1/agents/{id}/tasks             Poll pending jobs
POST   /v1/agents/{id}/tasks/{job_id}/events   Submit events    [60/min, 500/batch]
POST   /v1/agents/{id}/tasks/{job_id}/complete  Mark done/failed
GET    /v1/agents                        List agents (org-scoped)
GET    /v1/agents/{id}                   Agent detail
DELETE /v1/agents/{id}                   Deregister
POST   /v1/agents/{id}/activate         Enable agent
POST   /v1/agents/{id}/deactivate       Disable agent
```

### License / VDB / Settings

```
GET    /v1/license              License status
POST   /v1/license/activate     Activate key                    [3/hr/IP]
GET    /v1/vdb/status           VDB stats + freshness
POST   /v1/vdb/sync             Refresh from NVD (background)
GET    /v1/settings/ai          Get org AI config (key masked)
POST   /v1/settings/ai          Update org AI config (encrypted)
POST   /v1/settings/ai/test     Test AI connection
```

### System

```
GET    /health                  Service status + uptime
GET    /docs                    OpenAPI docs
GET    /redoc                   ReDoc docs
```

---

## Environment Variables

### Controller

| Variable | Default | Description |
|---|---|---|
| `NETLOGIC_ENV` | _(unset)_ | `production`/`prod` = secret validation at startup |
| `NETLOGIC_JWT_SECRET` | `changeme-in-production` | HS256 signing secret, ≥32 chars |
| `NETLOGIC_JWT_EXPIRY` | `3600` | JWT lifetime in seconds |
| `NETLOGIC_ADMIN_KEY` | `admin-changeme` | Admin credential, ≥32 chars in production |
| `NETLOGIC_API_KEYS` | _(empty)_ | Seed keys: `key1:org1,key2:org2,...` |
| `NETLOGIC_CORS_ORIGINS` | _(empty)_ | Allowed origins (CORS disabled if empty) |
| `NETLOGIC_PORT` | `8000` | Bind port |
| `NETLOGIC_HOST` | `0.0.0.0` | Bind address |
| `NETLOGIC_NO_BROWSER` | _(unset)_ | `1` disables auto-open |
| `NETLOGIC_OIDC_ISSUER` | _(unset)_ | Clerk Frontend API URL → OIDC login |
| `NETLOGIC_OIDC_AUDIENCE` | _(unset)_ | OIDC audience |
| `NETLOGIC_OIDC_DEFAULT_ORG` | _(unset)_ | Fallback org_id for OIDC users |
| `NETLOGIC_DATABASE_URL` | _(unset)_ | PostgreSQL connection string |
| `NETLOGIC_SECRETS_KEY` | _(unset)_ | Fernet key for credentials at rest |
| `NETLOGIC_AGENT_TOKEN_MAX_AGE` | `604800` | Agent token lifetime (7 days) |
| `NETLOGIC_AGENT_PENDING_CAP` | `50` | Max queued tasks per agent |
| `NETLOGIC_MAX_AGENTS_PER_ORG` | `100` | Max registered agents |
| `NETLOGIC_AI_PROVIDER` | `openrouter` | Default AI provider |
| `NETLOGIC_AI_API_KEY` | _(empty)_ | Default AI key |
| `NETLOGIC_AI_MODEL` | provider default | Default model |
| `NETLOGIC_AI_BASE_URL` | provider default | Custom base URL |
| `NETLOGIC_NVD_KEY` | _(empty)_ | NVD API key |
| `NETLOGIC_VALID_LICENSES` | _(empty)_ | Dev/test license overrides |
| `NETLOGIC_LICENSE_KEY` | _(empty)_ | Instance license key |
| `NETLOGIC_SCANS_DIR` | _(default)_ | Scan storage directory |
| `NETLOGIC_SIEM_ENDPOINT` | _(empty)_ | Audit log shipping URL |
| `NETLOGIC_WAPPALYZER_DATA` | _(built-in)_ | Wappalyzer fingerprints path |

### Agent

| Variable | Default | Description |
|---|---|---|
| `NETLOGIC_CONTROLLER` | `http://localhost:8000` | Controller base URL |
| `NETLOGIC_API_KEY` | _(unset)_ | API key for registration |

---

## Security Architecture

### Middleware stack (order applied)
1. **AuditMiddleware** — `X-Request-ID` correlation, structured JSON audit log, SIEM shipping
2. **RequestSizeLimitMiddleware** — 10 MB body limit (DoS protection)
3. **LicenseMiddleware** — blocks all `/v1/` routes when unlicensed (returns 402)
4. **SecurityHeadersMiddleware** — HSTS (1y), CSP (differentiated HTML vs API), X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy
5. **OriginCheckMiddleware** — POST/PUT/DELETE Origin validation (CSRF defence-in-depth)
6. **CORSMiddleware** — restrictive: no wildcard, specific origins only

### Authentication
- **API keys**: SHA-256 hashed at rest; plaintext only on `create()` and in request body during `verify()`
- **JWT**: HS256 with stdlib (`hashlib`+`hmac`+`base64`), `alg` field pinned before verification (prevents alg=none), ephemeral random fallback for dev
- **OIDC**: Clerk/Auth0/WorkOS — RS256 + JWKS, auto-provisions users + orgs on first login
- **Agent tokens**: SHA-256 hashed in registry, constant-time comparison, 7-day expiry

### Rate limiting
Sliding-window in-memory. Per-endpoint, per-scope (IP, org_id, agent_id). IP banning after 5 failed token exchanges in 10 minutes (1h ban).

### Data protection
- LLM API keys: Fernet-encrypted at rest (AES-128-CBC + HMAC-SHA256). Production-fail-closed: requires `NETLOGIC_SECRETS_KEY`
- Multi-tenancy: all data scoped to `org_id`; cross-org lookup returns 404 (not 403)
- Path traversal: all storage paths validated, separators and `..` rejected

---

## CI / Testing

```bash
pip install -r requirements-dev.txt
python -m pytest
```

CI pipeline (`.github/workflows/ci.yml`) — 5 jobs:
1. **test** — 1,000+ pytest cases
2. **postgres-integration** — DB migrations + durable jobs + per-org keys
3. **fusion-benchmark** — FP reduction ≥ 80% + critical recall = 100%
4. **security** — Bandit (HIGH) + `pip-audit`
5. **build-dashboard** — `npm ci` + `npm run build`

---

## Legal Notice

> **NetLogic is intended for authorized security assessments, penetration testing, and network administration only.**
> Scanning or probing hosts without explicit written permission is illegal in most jurisdictions.
> The author assumes no liability for unauthorized use.

---

## License

MIT © 2026 Dmitry Flynn — See [LICENSE.txt](LICENSE.txt)
