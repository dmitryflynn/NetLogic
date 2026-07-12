"""AI-driven adjudication (the AI resolves findings the deterministic engine can't verify).

The FindingAdjudicator RETURNS verdicts (pure data — isolation preserved); the director APPLIES
them: ruled_out → hypothesis refuted → investigation reads NOT EXPLOITABLE; likely_exploitable →
exploitable mass raised → POSSIBLY EXPLOITABLE; needs_active_check → stays an UNVERIFIED lead.
"""
import json

from src.reasoning.ai.agents import FindingAdjudicator
from src.reasoning.ai.transcript import InvestigationTranscript
from src.reasoning.investigations import group_investigations
from src.reasoning.objective import Objective
from src.reasoning.state import ReasoningState


def _state_with_stuck_cves():
    s = ReasoningState(target="scanme.example.org:22", scope=["scanme.example.org"])
    cn = s.world.graph.upsert_node("cve", "cve-2023-38408", label="CVE-2023-38408")
    s.world.graph.observe(cn, kind="vuln",
                          evidence="openssh 6.6.1p1 on 22/ssh: agent RCE via PKCS#11", source="nvd")
    # the pattern-matched CVE surfaces as a verify: objective + a stuck exploitability hypothesis
    # sitting at its prior — exactly the version-match dead end the engine can't resolve.
    s.investigation.objectives.add(Objective(name="verify:CVE-2023-38408", satisfied=True))
    s.investigation.hypotheses.add_hypothesis(
        label="exploitability_of:verify:CVE-2023-38408", created_by="rule",
        likelihoods={"exploitable": 0.35, "not_exploitable": 0.65})
    return s


def _completer(verdict, rationale="requires authenticated local shell — not remotely reachable"):
    """Default rationale is a valid positive ruled_out (local-only), not a weak 'backport' claim."""
    def complete(system, user):
        return json.dumps([{"cve": "CVE-2023-38408", "verdict": verdict,
                            "confidence": 0.8, "rationale": rationale}])
    return complete


def _apply(state, decisions):
    """Mirror the director's application step (kept out of the AI layer for isolation)."""
    hyps = {h.label: h for h in state.investigation.hypotheses.all()}
    for d in decisions:
        h = hyps.get(d["hypothesis_label"])
        if h is None or h.status != "active":
            continue
        if d["verdict"] == "ruled_out":
            state.investigation.hypotheses.resolve(h.id, "refuted")
        elif d["verdict"] == "likely_exploitable":
            h.likelihoods = {"exploitable": 0.6, "not_exploitable": 0.4}
        h.ai_adjudicated = True
        h.ai_rationale = d["rationale"]


def test_adjudicator_returns_decisions_but_mutates_nothing():
    s = _state_with_stuck_cves()
    before = json.dumps(s.to_dict(), sort_keys=True, default=str)
    decisions = FindingAdjudicator(_completer("ruled_out")).decide(s)
    after = json.dumps(s.to_dict(), sort_keys=True, default=str)
    assert before == after                       # the agent is a pure reader
    assert len(decisions) == 1
    assert decisions[0]["verdict"] == "ruled_out"
    assert decisions[0]["hypothesis_label"] == "exploitability_of:verify:CVE-2023-38408"


def test_weak_backport_ruled_out_is_demoted_to_needs_active_check():
    """Policy guard: 'Ubuntu backports' alone cannot close a CVE as NOT EXPLOITABLE."""
    s = _state_with_stuck_cves()
    decisions = FindingAdjudicator(
        _completer("ruled_out", "ubuntu backports the fix without changing the banner")
    ).decide(s)
    assert decisions[0]["verdict"] == "needs_active_check"
    assert "demoted" in decisions[0]["rationale"].lower() or "policy" in decisions[0]["rationale"].lower()


def test_ruled_out_makes_the_cve_read_not_exploitable():
    s = _state_with_stuck_cves()
    # baseline: unresolved → UNVERIFIED
    ex = next(i for i in group_investigations(s) if i.kind == "exploitability")
    assert ex.conclusion == "UNVERIFIED"
    _apply(s, FindingAdjudicator(
        _completer("ruled_out", "local privilege escalation — requires authenticated shell")
    ).decide(s))
    ex = next(i for i in group_investigations(s) if i.kind == "exploitability")
    assert ex.conclusion == "NOT EXPLOITABLE"
    assert ex.adjudicated_by_ai is True
    assert "local" in ex.rationale.lower() or "shell" in ex.rationale.lower()


def test_likely_exploitable_reads_as_possibly_never_confirmed():
    s = _state_with_stuck_cves()
    _apply(s, FindingAdjudicator(_completer("likely_exploitable", "socket exposed")).decide(s))
    ex = next(i for i in group_investigations(s) if i.kind == "exploitability")
    assert ex.conclusion == "POSSIBLY EXPLOITABLE"     # NOT "EXPLOITABLE" — no confirmed vuln from a bare LLM
    assert ex.adjudicated_by_ai is True


def test_needs_active_check_stays_an_unverified_lead():
    s = _state_with_stuck_cves()
    _apply(s, FindingAdjudicator(_completer("needs_active_check")).decide(s))
    ex = next(i for i in group_investigations(s) if i.kind == "exploitability")
    assert ex.conclusion == "UNVERIFIED"


def test_broken_ai_yields_no_decisions():
    s = _state_with_stuck_cves()
    def boom(system, user):
        raise RuntimeError("model down")
    assert FindingAdjudicator(boom).decide(s) == []
    def garbage(system, user):
        return "not json at all {{{"
    assert FindingAdjudicator(garbage).decide(s) == []


def test_adjudicator_ignores_cves_it_wasnt_given():
    # the AI can't adjudicate a CVE that isn't an open finding (anti-hallucination)
    s = _state_with_stuck_cves()
    def rogue(system, user):
        return json.dumps([{"cve": "CVE-9999-0000", "verdict": "ruled_out",
                            "confidence": 1.0, "rationale": "made up"}])
    assert FindingAdjudicator(rogue).decide(s) == []


def test_transcript_note_records_the_ai_judgement():
    t = InvestigationTranscript()
    t.record_note(agent="finding_adjudicator", summary="CVE-2023-38408 → ruled_out",
                  rationale="backport", outcome="refuted")
    d = t.to_dict()
    assert d["summary"]["accepted"] == 1
    assert d["entries"][0]["agent"] == "finding_adjudicator"
    assert d["entries"][0]["outcome"] == "refuted"
