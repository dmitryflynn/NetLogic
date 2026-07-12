"""
Multi-host expansion + dispatch (Phase 6c) — activation behind a default-OFF flag.

Scope expansion is expressed with the Phase 5 `Candidate` machinery, not a bespoke scheduler: a
**HostCandidate** is a `Candidate(source="cross_host")` whose `instantiate()` asks `HostManager` to
create a `HostReasoner` for an **authorized** neighbor. Matching the lazy philosophy everywhere else,
no reasoning context is created until the policy *selects* the candidate.

Flow per cycle (only when `world_modeling_enabled`):
    derive edges → ScopeAuthorizer.evaluate → AUTHORIZE only → HostCandidate[]
        → DecisionPolicy.rank_candidates → instantiate top-K → HostManager spawns HostReasoner[]
        → dispatch: run each host's pipeline (loop level, not inside a host's reasoning)
"""
from __future__ import annotations

from typing import Callable

from src.reasoning.candidate import Candidate
from src.reasoning.cross_host import AuthDecision, ScopeAuthorizer, derive_cross_host_edges

BuildHostState = Callable[[str], object]   # host -> a fresh ReasoningState for that host
RunHost = Callable[[object], None]         # HostReasoner -> None (run its per-host pipeline)


def make_host_candidate(edge, host_manager, build_host_state: BuildHostState,
                        *, gain: float) -> Candidate:
    """A lazy expansion action. instantiate() creates the neighbor's HostReasoner via HostManager
    (the effect of selecting expansion) and returns no Intents — the new host is reasoned over by the
    dispatch loop. Building/ranking the candidate creates nothing (the lazy boundary)."""
    def _factory():
        if edge.dest_host not in host_manager:
            host_manager.create(edge.dest_host, build_host_state(edge.dest_host))
        return []
    return Candidate.deferred(
        source="cross_host",
        kind=f"expand:{edge.dest_host}",
        gain=gain,
        rationale=(f"cross_host {edge.source_host}->{edge.dest_host} "
                   f"({edge.source_kind}, conf={edge.confidence})"),
        factory=_factory,
    )


def host_expansion_candidates(world_state, scope: list[str], authorizer: ScopeAuthorizer,
                              build_host_state: BuildHostState) -> list[Candidate]:
    """One HostCandidate per AUTHORIZED, not-yet-investigated neighbor. Pure: instantiates nothing."""
    edges = derive_cross_host_edges(world_state.environment.evidence_graph)
    # Record derived structure on the environment graph (facts only).
    for e in edges:
        world_state.environment.cross_host_graph.add_edge(e)

    candidates: list[Candidate] = []
    for e in edges:
        if e.dest_host in world_state.hosts:
            continue
        if authorizer.evaluate(e, scope) is AuthDecision.AUTHORIZE:
            candidates.append(make_host_candidate(
                e, world_state.hosts, build_host_state, gain=2.0 * e.confidence))
    return candidates


def expand_world(world_state, scope: list[str], authorizer: ScopeAuthorizer,
                 build_host_state: BuildHostState, policy, *, max_new_hosts: int = 3) -> list[str]:
    """Derive → authorize → rank → instantiate top-K. Returns the names of newly created hosts."""
    candidates = host_expansion_candidates(world_state, scope, authorizer, build_host_state)
    if not candidates:
        return []
    before = {hr.host for hr in world_state.hosts.all()}
    for ranked in policy.rank_candidates(candidates)[:max_new_hosts]:
        ranked.candidate.instantiate()      # lazy effect: spawn the HostReasoner
    after = {hr.host for hr in world_state.hosts.all()}
    return sorted(after - before)


def dispatch(world_state, run_host: RunHost) -> list[str]:
    """Loop-level multi-host dispatch: run each host's pipeline once (skipping exhausted budgets).
    Dispatch is at the loop level, never inside a single host's reasoning. Returns hosts run."""
    ran: list[str] = []
    for hr in world_state.hosts.all():
        # hr.state carries its own BudgetManager via the director; here we honor an explicit one if set
        bm = getattr(hr, "budget_manager", None)
        if bm is not None and bm.exhausted():
            continue
        run_host(hr)
        ran.append(hr.host)
    return ran
