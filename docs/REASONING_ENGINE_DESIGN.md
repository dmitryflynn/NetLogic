# NetLogic Reasoning Engine — Architecture Design (v3)

> **Status:** Design (no implementation yet). Defines `src/reasoning/`, the persistent
> reasoning subsystem that turns NetLogic into an AI-driven reconnaissance operating system.
>
> **v3 changes:** added a meta-reasoning `StrategyManager` above `ReconDirector`; an explicit
> `Scheduler` component; first-class `Objective`s; environment-wide **multi-host** reasoning;
> reusable investigation **Playbooks**; **confidence decay**; first-class **Explainability**.
> (v2 added hierarchical state, ProbePlan trees, temporal EvidenceGraph, personas,
> hypothesis trees, information-gain scheduling, exploration/exploitation.)

---

## 1. Context & principle

Today AI is invoked as **isolated modules** at fixed points in a 727-line linear pipeline
(`src/engine.py::run_scan`); each starts cold, reasons once, discards context. The scan
can't carry a hypothesis forward or reason across hosts.

**Goal:** a persistent, hierarchical reasoning state plus a meta-governed adaptive loop, so
the AI reasons continuously across the whole **environment** at the level of reconnaissance
strategy, while a deterministic kernel executes validated steps.

**Principle (already true in fusion — preserve it):** the LLM reasons; deterministic Python
executes. The model never touches a socket; it emits structured plans the kernel validates,
compiles, and runs.

---

## 2. Component hierarchy (the control stack)

The key v3 change: a **meta-reasoning layer** owns *how the investigation evolves*, so
`ReconDirector` only runs the loop and never accumulates strategy logic.

```
StrategyManager     # META: how the investigation evolves (reasons about its own reasoning)
   ↓
ReconDirector       # runs one observe→reason→act cycle under the strategy in force
   ↓
HypothesisEngine    # competing hypotheses (a forest)
   ↓
Scheduler           # scores candidate actions by information gain; applies explore/exploit
   ↓
ProbePlanner        # emits ProbePlan trees (instantiates Playbooks, AI-customizes)
   ↓
ExecutionKernel     # validates → compiles → executes (the only thing touching the network)
```

### 2.1 `StrategyManager` — meta-reasoning (new, the top layer)

Reasons about the engine's *own* reasoning, not the target. Detects when the current
approach is failing and changes it. It owns everything that governs investigation evolution:

- **Persona transitions** (§7) — pick/switch investigative mode.
- **Exploration vs exploitation policy** (§6.1) — the budget split the Scheduler obeys.
- **Stopping conditions** (§9) — when to halt.
- **Investigation restarts** — e.g. "37 probes spent, information gain has plateaued, my
  assumptions may be wrong → restart under a different persona."
- **Budget reallocation** — shift remaining budget between objectives/hosts.
- **Escalation** — promote a host/objective to higher priority on a strong signal.
- **Objective reprioritization** (§4) — re-rank what the Scheduler optimizes.

Inputs: plateau/entropy signals from the Scheduler + ExecutionState history. Outputs:
strategy directives consumed by `ReconDirector`. Keeping this separate is what stops
`ReconDirector` from becoming a 2,000-line orchestrator.

### 2.2 `ReconDirector` — loop executor

Runs a single observe→reason→act cycle (§8) under the strategy `StrategyManager` set. No
strategy logic of its own.

### 2.3 `Scheduler` — information-gain action selection (new, promoted from v2 §5)

Scores every candidate action — a ProbePlan, a pure-reasoning step, or *nothing* — and
returns the best, subject to the StrategyManager's explore/exploit policy (§6.1):

```
Priority(action) = (ExpectedInformationGain × ConfidenceReduction)
                   ÷ (Cost × Time × TokenUsage × ProbeRisk)
```

Entropy/gain math is deterministic; the model only supplies per-outcome likelihoods.

---

## 3. Hierarchical, environment-wide reasoning memory

```
ReasoningState   (persisted to Postgres job store — §11.4)
├── WorldModel          # what EXISTS across the whole ENVIRONMENT (multi-host) + decay
├── InvestigationState  # objectives, goals, hypothesis forest, unknowns, persona
├── ExecutionState      # budgets, probe ledger, history, explanations
└── LearnedPatterns     # cross-scan heuristics + discovered Playbooks (later)
```

### 3.1 `WorldModel` — environment, not a single host

**Multi-host is core, not an add-on.** The WorldModel models the whole authorized
environment: a set of hosts, each a subgraph of the **EvidenceGraph** (§5), connected by
**cross-host edges** (generalizing `fusion/cross_host` + `directors/subnet_director`). This
lets the engine reason across the environment:

```
mail.example.com → OWA → Exchange ⇒ exchange.example.com likely exists → autodiscover likely
GitLab → Registry → Runner → Kubernetes → cloud metadata
```

A confirmed service can **infer the likely existence of related hosts/endpoints**, spawning
new objectives and nodes — all still constrained to `scope` by the kernel (§10). Holds
`technology_graph`, `attack_graph`, `reachability`, `potential_pivots`, `interesting_*`.

### 3.2 `InvestigationState` — objectives, goals, hypotheses

Adds first-class **`Objective`s** (§4) above goals/hypotheses, plus the hypothesis **forest**
(§6), `unknowns`, current `persona`, `contradictions`, `dead_ends`.

### 3.3 `ExecutionState`

`budget`, the probe ledger (MemoryStore), `execution_history`, `failed_probes`, and the
**Explanation** records (§10) for every action.

### 3.4 `LearnedPatterns` (later)

Cross-scan priors + a catalog of **Playbooks** (§8.1) promoted from successful investigations.
Off by default; fed by persistence.

---

## 4. `Objective`s — what the planner optimizes (new)

Goals and hypotheses describe *belief*; **Objectives** describe *intent*, and are the unit the
Scheduler optimizes toward.

```
Objective:
  name:        "Identify application framework"
  priority:    0.92                       # set/adjusted by StrategyManager
  satisfied:   false
  dependencies: ["HTTP fingerprint complete"]   # objectives/edges that must exist first
  produced_by: "Technology persona"
  consumed_by: ["CVE verifier"]
  host_scope:  per-host | environment      # supports multi-host objectives
```

Objectives form a dependency DAG; the Scheduler only pursues objectives whose dependencies
are met, and the StrategyManager reprioritizes them as evidence shifts.

---

## 5. `EvidenceGraph` — temporal, typed, multi-host

Generalizes `fusion/synthesis.AttackGraph` + `fusion/cross_host`. Nodes: Port, Service,
Version, Header, Cookie, Certificate, DNS, ASN, Framework, CMS, Cloud, WAF, Technology,
Vulnerability, Misconfiguration, Directory, File, Endpoint, Authentication, Response, **Host**.

**Every edge is temporal and explained:**
```
Edge: type, source, target, evidence, timestamp, confidence,
      source_probe,    # which ProbeSpec produced it (or "passive")
      dependencies     # edges it was derived from
```
Cross-host edges (`reachable_from`, `infers_host`, `shares_cert`, `same_asn`) make §3.1
environment reasoning first-class. Temporal+provenance answers "why do we believe this?"
deterministically and powers UI replay.

---

## 6. `HypothesisEngine` — hypothesis forest

Hypotheses are a forest; resolving a parent **spawns children** (Spring Boot → Spring
Security → Actuator? → GraphQL? → k8s? → cloud vendor?). The model proposes hypotheses +
per-outcome likelihoods; entropy/normalization/info-gain are deterministic.

### 6.1 Exploration vs exploitation (policy owned by StrategyManager)

A UCB-style policy reserves a budget fraction (default ~10%) for high-uncertainty / low-
confidence branches so the Scheduler doesn't tunnel into the leading hypothesis and miss an
entirely different attack surface. The StrategyManager sets the split; the Scheduler obeys it.

---

## 7. Investigation personas

`ReconDirector` operates in an explicit persona that reweights the Priority function;
`StrategyManager` transitions between them:

```
Service Discovery → Technology Fingerprinting → Cloud Discovery → Application Mapping
  → Misconfiguration Discovery → CVE Verification → Pivot Discovery
```

`directors/sensor_director` becomes the **advisor** proposing the next persona + sensor
emphasis.

---

## 8. Investigation plans (probe trees) + Playbooks

The planner emits **`ProbePlan`s — trees**, not isolated probes: conditional branches,
retries, exits. A `ProbeSpec` is a node. The kernel walks the tree, evaluating branch
conditions deterministically against returned evidence.

```
ProbePlan
├── Probe: GET /
├── Conditional: if GraphQL → introspection
│   ├── if blocked → fingerprint GraphQL framework
│   └── else       → extract schema
├── Conditional: else → find alternate API endpoint
├── Retry policy / Exit conditions per node
```

`ProbeSpec` node fields: `id, hypothesis_id, objective_id, parent_node, transport,
protocol, target_host, target_port (∈ scope), request_spec, purpose, expected_evidence,
branch_conditions, confidence_gain, estimated_cost{time_ms,tokens}, risk_level=read_only,
timeout_ms, retry_policy, termination_conditions`.

### 8.1 Playbooks — reusable investigation graphs (new)

The planner doesn't always build a tree from scratch. A **Playbook** is a reusable
investigation graph (e.g. a 15-node "Spring Boot Investigation"). The planner **instantiates**
a matching Playbook and asks the AI only for the **delta** (customizations), saving tokens
while staying adaptive. Successful dynamic plans get promoted into `LearnedPatterns` (§3.4)
as new Playbooks.

Strategy layer over existing planners: `verifier/planner` (already emits this shape),
`directors/reprobe`, `nuclei_selector`, `deep/probe_agent`.

---

## 9. `ExecutionKernel` — hybrid adaptive execution (safety-critical)

The only thing that talks to the network; generalizes `deep/sandbox.gen_poc_http/connect`.
Walking a `ProbePlan`, every node passes a deterministic validation pipeline before any byte
is sent: **scope → transport/protocol compatibility → read-only-recon-only → protocol
correctness → recursion depth → timeout → rate limit → duplicate detection → budget →
compile+execute**. Existing libraries (`vuln_prober`, `service_prober`, `verifier/runner`,
`deep/sandbox`) stay as optimized primitives; novel plans use the generic compiler.

### Stopping conditions (owned by StrategyManager)

Halt when any holds: best remaining Priority < threshold; goal/objective confidence >
threshold; budget exhausted; max recursion reached; no high-value actions remain.

---

## 10. Confidence, decay & explainability

### 10.1 `ConfidenceEngine` + decay

Aggregates `fusion.Signal`s by `subject_key()` into a posterior (corroboration↑,
contradiction↓; `probe_confirmed` pins; **`version_matched` caps below "confirmed"** — the
single home of the `gate.py` fix, §13). **New: confidence decays over time and on conflicting
evidence.** A belief ("Server: nginx") loses confidence as it ages or when later evidence
(changed headers) contradicts it, which can re-open an objective and restart investigation.
Essential for long-running scans and future continuous monitoring.

### 10.2 Explainability (first-class)

Every probe and every StrategyManager decision carries a deterministic **Explanation**:

```
Explanation:
  objective, hypothesis, evidence_refs,
  expected_information_gain, budget_cost, decision, timestamp
```

Stored in ExecutionState and backed by temporal EvidenceGraph edges (§5), so "why did we do
this?" always has a concrete, auditable answer. Invaluable for debugging and a candidate for
direct UI exposure.

---

## 11. Resolved decisions

1. **Budget defaults** — hosted tier: conservative ceilings (wall-clock/probe/token) for
   predictability; local `--gui`: user-raisable. `BudgetManager` is tier-aware.
2. **Adaptive trigger** — deterministic sweep first; enter the loop only if confidence is low,
   high-value unknowns remain, or contradictions exist.
3. **`raw`/custom-binary protocol** — explicit per-scan opt-in until the validation + injection
   test suite is mature.
4. **Persistence** — `ReasoningState` persists to the Postgres job store: post-scan analysis,
   UI replay (temporal edges + explanations), resuming interrupted scans, scan-over-time
   comparison, and `LearnedPatterns`/Playbook training.

---

## 12. Safety & trust model (non-negotiable)

- **Authorized scope enforced in code, every probe, every iteration** — incl. inferred
  multi-host targets (§3.1). The CFAA boundary; ties to `docs/DESIGN_PARTNER_PACK.md`.
- **Target-derived text is untrusted DATA, never instructions** — reuse `Signal.ai_view()`
  (`fusion/signals.py`) severity/name stripping; kernel constrains targets to `scope`
  regardless of model output.
- **Read-only reconnaissance only**; **bounded everything**; **fail-closed in production**
  (consistent with `api/crypto.py`).

---

## 13. Module map + foundation fixes

| Existing | Becomes |
|---|---|
| `engine.py::run_scan` | initial OBSERVE sweep + host for `ReconDirector` |
| `directors/sensor_director` | persona/sensor **advisor** to `StrategyManager` |
| `directors/reprobe`, `nuclei_selector` | `ProbePlanner` strategies/advisors |
| `directors/subnet_director` + `fusion/cross_host` | core multi-host reasoning (§3.1, §5) |
| `verifier/{engine,planner,runner}` | planner strategy + kernel primitive |
| `deep/{coordinator,probe_agent,scout_agent}` | execution workers under the kernel |
| `deep/sandbox` | kernel spec→request compiler seed |
| `fusion/{gate,adjudicator,signals}` | `ConfidenceEngine` (+ decay) |
| `fusion/{synthesis,cross_host}` | `EvidenceGraph` views |

**Foundation fixes folded into Phase 0:** `gate.py` version-only "Confirmed CRITICAL" →
centralized version-matched cap in ConfidenceEngine; `SensorDirector` `'ServiceBanner' object
is not subscriptable` → dies when the director consumes typed `ReasoningState` Observations.

---

## 14. Backwards compatibility

No AI key → one OBSERVE iteration = today's exact deterministic output. `_emit(...)` preserved
(+ new `reasoning`/`hypothesis`/`probe_plan`/`explanation` events). All CLI flags keep working.

---

## 15. Phased rollout

- **Phase 0** — fix foundation bugs; scaffold `src/reasoning/` with hierarchical
  `ReasoningState` (WorldModel/InvestigationState/ExecutionState) + `MemoryStore`. No behavior
  change.
- **Phase 1** — temporal multi-host `EvidenceGraph` + `ConfidenceEngine` (+ decay) from existing
  emitters; Postgres persistence; Explanation records. Output unchanged.
- **Phase 2** — `StrategyManager` + `ReconDirector` loop + personas + `Scheduler`, wrapping the
  pipeline; adaptive trigger; `sensor_director`/`reprobe` as strategies.
- **Phase 3** — `HypothesisEngine` (forest) + explore/exploit + `ProbePlanner` (ProbePlan trees
  + Playbooks) + `ExecutionKernel` full validation; `raw` behind opt-in; `Objective` DAG.
- **Phase 4** — `LearnedPatterns` + Playbook promotion; multi-host inference depth; arch-doc
  rewrite; e2e tests; adaptive-vs-deterministic benchmark.

---

## 16. Testing strategy

- **Unit:** ConfidenceEngine convergence + **decay**; EvidenceGraph temporal/cross-host
  invariants; Scheduler info-gain + explore/exploit; hypothesis-forest entropy; Objective DAG
  dependency gating; StrategyManager restart/persona-switch triggers; ProbePlan branch eval;
  Playbook instantiation; MemoryStore dedup; BudgetManager ceilings.
- **Safety (highest priority):** kernel rejects off-scope (incl. inferred hosts), non-read-only,
  malformed, duplicate, over-budget, over-depth. **Injection corpus:** adversarial banners/HTML
  must not change probe targets, personas, or spawn off-scope hosts.
- **Meta-reasoning:** plateau detection triggers restart; contradictory-evidence decay re-opens
  an objective.
- **Loop:** cassette-driven (`fusion/cassette.py`) full runs asserting termination + "no probe"
  decisions + explanations present.
- **Regression:** scan output byte-identical with no AI key.
- **Benchmark:** adaptive precision/recall vs deterministic; assert no critical-recall regression.
