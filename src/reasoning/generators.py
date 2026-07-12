"""
Deterministic generators — the baseline producers of objectives, hypotheses, and intents.

See the Phase 3 Activation plan §2. These read the EvidenceGraph + beliefs and populate the
ObjectiveDAG and HypothesisEngine using deterministic rules — the minimum-viable behavior that
needs no AI key and is fully testable. AI is an *optional augmentation* layer added on top
(the Track C cognitive agents can contribute extra hypotheses/intents); it improves quality but is
never required. Generators are idempotent: re-running on the same state adds nothing new.
"""
from __future__ import annotations

from src.reasoning.intent import EvidenceType, Intent, IntentConstraints
from src.reasoning.objective import Objective
from src.reasoning.state import ReasoningState

_HIGH_IMPACT = {"high", "critical"}
_ACTIVATE_CONF = 0.60

# Candidate frameworks for an unidentified HTTP service, seeded with uniform-ish priors.
_FRAMEWORK_CANDIDATES = {"spring_boot": 0.25, "express": 0.2, "django": 0.2,
                         "wordpress": 0.2, "custom": 0.15}

# Competing exploitability outcomes for an unverified CVE — genuine pre-verification uncertainty.
# Seeded toward "not exploitable" since most matched CVEs aren't reachable/applicable until proven.
_EXPLOITABILITY_CANDIDATES = {"exploitable": 0.35, "not_exploitable": 0.65}

# Objective-name prefix → the EvidenceTypes that discriminate it.
_OBJECTIVE_EVIDENCE = {
    "identify_framework": ["server_header", "http_headers", "http_body", "framework"],
    "identify_service": ["banner", "service"],
    "verify": ["cve", "banner"],
    "tls_posture": ["tls_version", "tls_alpn"],
    "dns_posture": ["dns_records"],
}


def populate_objectives(state: ReasoningState) -> list[Objective]:
    """Add deterministic objectives derived from the current beliefs/graph. Idempotent."""
    dag = state.investigation.objectives
    added: list[Objective] = []

    def _add(obj: Objective) -> None:
        if obj.name not in dag:
            dag.add(obj)
            added.append(obj)

    # 1. Version-only high/critical beliefs → verification objectives (high priority).
    for b in state.world.belief_records:
        if (b.get("version_only") and b.get("impact") in _HIGH_IMPACT
                and float(b.get("confidence", 1.0)) < _ACTIVATE_CONF):
            _add(Objective(name=f"verify:{b.get('claim', '')}", priority=0.9,
                           produced_by="generator"))

    # 2. HTTP service with no technology identified → identify the framework.
    if not state.world.technology:
        for node in state.world.graph.nodes("service"):
            _add(Objective(name=f"identify_framework:{node.key}", priority=0.6,
                           produced_by="generator"))

    # 3. Open port with no banner observation → identify the service.
    for node in state.world.graph.nodes("service"):
        has_banner = any(o.kind in ("banner", "service") for o in node.observations())
        if not has_banner:
            _add(Objective(name=f"identify_service:{node.key}", priority=0.4,
                           produced_by="generator"))
    return added


def populate_hypotheses(state: ReasoningState) -> list[str]:
    """For each identify_framework objective, add one hypothesis whose likelihoods are the
    competing-framework distribution (so its entropy reflects the genuine uncertainty). The
    distribution lives on a single node — `spawn_children` is for *deepening* a confirmed
    branch later, not for the initial competing set. Idempotent."""
    engine = state.investigation.hypotheses
    existing = {h.reason for h in engine.all() if h.reason}
    spawned: list[str] = []
    for obj in state.investigation.objectives.unsatisfied():
        if obj.name in existing:
            continue
        # Unidentified framework → competing-framework distribution.
        if obj.name.startswith("identify_framework:"):
            hid = engine.add_hypothesis(label=f"framework_of:{obj.name}", created_by="rule",
                                        likelihoods=dict(_FRAMEWORK_CANDIDATES), reason=obj.name)
            spawned.append(hid)
        # Unverified CVE → competing exploitability outcome (exploitable vs not). This makes the
        # forest reflect the genuine uncertainty of every matched-but-unproven CVE, the common case.
        elif obj.name.startswith("verify:"):
            hid = engine.add_hypothesis(label=f"exploitability_of:{obj.name}", created_by="rule",
                                        likelihoods=dict(_EXPLOITABILITY_CANDIDATES), reason=obj.name)
            spawned.append(hid)
    return spawned


def evidence_for(obj) -> list[str]:
    """The EvidenceType values that discriminate an objective. An objective's OWN `desired_evidence`
    (set by C2, the Investigation Designer, for AI-invented objectives) takes precedence; otherwise
    fall back to the static prefix→evidence table for the deterministic objectives. This is the one
    seam that lets an AI-generated objective become investigable by the ordinary Phase-3 loop."""
    if getattr(obj, "desired_evidence", ()):
        return list(obj.desired_evidence)
    return list(_OBJECTIVE_EVIDENCE.get(obj.name.split(":", 1)[0], []))


def generate_intents(state: ReasoningState) -> list[Intent]:
    """Build intents from ready, unsatisfied objectives, requesting the EvidenceTypes that
    discriminate them (deterministic). Replaces the keyword stub in the director."""
    intents: list[Intent] = []
    for obj in state.investigation.objectives.ready():
        if obj.satisfied:
            continue
        ev_values = evidence_for(obj)
        mapped = [et for et in EvidenceType if et.value in ev_values]
        if not mapped:
            continue
        intents.append(Intent(
            objective_id=obj.name, target_ref=state.target, goal=obj.name,
            desired_evidence=mapped, constraints=IntentConstraints(read_only=True),
            rationale=f"deterministic generator for {obj.name}",
        ))
    return intents


def populate(state: ReasoningState) -> None:
    """Run all deterministic generators in order. Idempotent."""
    populate_objectives(state)
    populate_hypotheses(state)
