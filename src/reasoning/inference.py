"""
InferenceEngine — deterministic Evidence → meaning.

See the Phase 4 plan §3. This owns the *semantics* of evidence: given the observations gathered
by the kernel, it confirms/refutes the competing-framework hypotheses, detects contradictions,
attributes evidence, and satisfies objectives by content (not just evidence type). It is
deterministic and rule-driven.

Boundaries (kept clean):
  • Rules are **pure data** loaded from `rules/*.json` (no Python matchers, no state, no IO at
    match time) — so inference is cacheable and replayable.
  • The InferenceEngine NEVER writes confidence. It emits `EvidenceMatch`/`InferenceStep`
    provenance and resolves hypotheses; belief confidence remains owned solely by the
    ConfidenceEngine (fed by signals on the next refresh).
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("netlogic.reasoning.inference")

_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


@dataclass(frozen=True)
class Rule:
    """A pure, declarative framework signature. Matchers are lower-cased substrings checked
    against the concatenated evidence blob."""
    name: str
    confirm: tuple = ()
    refute: tuple = ()
    contradiction: tuple = ()


@dataclass(frozen=True)
class EvidenceMatch:
    framework: str
    kind: str                # "confirm" | "refute" | "contradiction"
    matched: str             # the substring that matched
    rule: str


@dataclass(frozen=True)
class InferenceStep:
    """Provenance for one inference: evidence → rule → hypothesis change → objective."""
    hypothesis_id: str
    rule: str
    decision: str            # "confirmed" | "refuted" | "contradiction"
    matched: str
    objective_satisfied: str = ""
    evidence_refs: tuple = ()


class RuleLoader:
    """Loads declarative rule packs from JSON. Pure: no state beyond the loaded rules."""

    @staticmethod
    def load(directory: str = _RULES_DIR) -> dict[str, Rule]:
        rules: dict[str, Rule] = {}
        try:
            names = [f for f in os.listdir(directory) if f.endswith(".json")]
        except OSError:
            return rules
        for fname in sorted(names):
            try:
                with open(os.path.join(directory, fname), encoding="utf-8") as fh:
                    data = json.load(fh)
                name = str(data["name"]).lower()
                rules[name] = Rule(
                    name=name,
                    confirm=tuple(str(s).lower() for s in data.get("confirm", [])),
                    refute=tuple(str(s).lower() for s in data.get("refute", [])),
                    contradiction=tuple(str(s).lower() for s in data.get("contradiction", [])),
                )
            except Exception as exc:  # noqa: BLE001 — a bad pack is skipped, not fatal
                log.warning("skipping rule pack %s (%s)", fname, exc)
        return rules


class InferenceEngine:
    def __init__(self, rules: Optional[dict[str, Rule]] = None) -> None:
        self._rules = rules if rules is not None else RuleLoader.load()

    def infer(self, state) -> list[InferenceStep]:
        """Resolve competing-framework hypotheses from observed evidence. Returns the trace."""
        blob = self._evidence_blob(state)
        steps: list[InferenceStep] = []
        for h in state.investigation.hypotheses.leaves():
            if len(h.likelihoods) < 2:           # only competing-candidate hypotheses
                continue
            confirmed = [(fw, m) for fw in h.likelihoods for m in self._matches(fw, blob, "confirm")]
            refuted = {fw for fw in h.likelihoods for _ in self._matches(fw, blob, "refute")}
            distinct_confirmed = {fw for fw, _ in confirmed}

            if len(distinct_confirmed) >= 2:
                # two frameworks both positively matched → contradictory evidence
                state.investigation.contradictions.append(
                    {"signal": f"multiple frameworks matched: {sorted(distinct_confirmed)}",
                     "source": "inference", "hypothesis": h.id})
                steps.append(InferenceStep(hypothesis_id=h.id, rule="multi",
                                           decision="contradiction",
                                           matched=",".join(sorted(distinct_confirmed))))
                continue

            if len(distinct_confirmed) == 1:
                fw, match = confirmed[0]
                if fw in refuted:                # confirmed and refuted → contradiction, skip
                    continue
                obj = self._objective_for(state, h)
                state.investigation.hypotheses.resolve(h.id, "confirmed", evidence_refs=[match.matched])
                if obj:
                    try:
                        state.investigation.objectives.satisfy(obj)
                    except KeyError:
                        pass
                steps.append(InferenceStep(hypothesis_id=h.id, rule=match.rule,
                                           decision="confirmed", matched=match.matched,
                                           objective_satisfied=obj or "",
                                           evidence_refs=(match.matched,)))
        return steps

    # ── Internals (pure) ──
    def _matches(self, framework: str, blob: str, kind: str) -> list[EvidenceMatch]:
        rule = self._rules.get(str(framework).lower())
        if not rule:
            return []
        needles = {"confirm": rule.confirm, "refute": rule.refute,
                   "contradiction": rule.contradiction}.get(kind, ())
        return [EvidenceMatch(framework=framework, kind=kind, matched=n, rule=rule.name)
                for n in needles if n and n in blob]

    @staticmethod
    def _evidence_blob(state) -> str:
        parts: list[str] = []
        for node in state.world.graph.nodes():
            for o in node.observations():
                if o.evidence:
                    parts.append(str(o.evidence))
                if o.data:
                    parts.append(json.dumps(o.data, default=str))
        return " ".join(parts).lower()

    @staticmethod
    def _objective_for(state, hypothesis) -> str:
        # hypotheses carry the objective name in `reason` (set by the generators / proposer)
        reason = (hypothesis.reason or "").split(":ai")[0]
        if reason and reason in state.investigation.objectives:
            return reason
        return ""
