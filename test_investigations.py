"""Investigation grouping — the human-readable view: dozens of raw objectives regrouped into a few
analyst-style investigations (Question / Evidence checklist / Conclusion / Confidence). Pure derivation."""
from src.reasoning.investigations import Investigation, group_investigations
from src.reasoning.objective import Objective
from src.reasoning.state import ReasoningState


def _state():
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    cn = s.world.graph.upsert_node("cve", "cve-2021-31166", label="CVE-2021-31166")
    s.world.graph.observe(cn, kind="vuln", evidence="iis 10.0: IIS HTTP.sys UAF RCE", source="nvd")
    for name, sat in [("verify:CVE-2021-31166", True),
                      ("refute:not_exploitable:version_check_vulnerable_range", False),
                      ("refute:not_exploitable:reachable_endpoint", True),
                      ("identify_framework:ex.com:80", True),
                      ("novel:cache_poisoning", False)]:
        s.investigation.objectives.add(Objective(name=name, satisfied=sat))
    return s


def test_unresolved_version_match_reads_as_unverified_not_confident():
    # A CVE whose exploitability hypothesis is still at its prior (never resolved) must NOT
    # be reported as "likely not exploitable" — the engine verified nothing. It is a lead.
    s = _state()
    s.investigation.hypotheses.add_hypothesis(
        label="exploitability_of:verify:CVE-2021-31166", created_by="rule",
        likelihoods={"exploitable": 0.35, "not_exploitable": 0.65})
    invs = group_investigations(s)
    ex = next(i for i in invs if i.kind == "exploitability")
    assert ex.question == "Can CVE-2021-31166 be exploited?"
    assert ex.conclusion == "UNVERIFIED"
    # honest evidence: matched from a banner, not independently verified — and the unrelated
    # global refute checklist is NOT stapled on
    names = {e.name for e in ex.evidence}
    assert any("version banner" in n for n in names)
    assert "version_check_vulnerable_range" not in names and "reachable_endpoint" not in names
    # and the CVE description is still surfaced in the subject
    assert "HTTP.sys" in ex.subject


def test_confirmed_exploitable_reads_as_exploitable():
    s = _state()
    hid = s.investigation.hypotheses.add_hypothesis(
        label="exploitability_of:verify:CVE-2021-31166", created_by="rule",
        likelihoods={"exploitable": 0.8, "not_exploitable": 0.2})
    s.investigation.hypotheses.resolve(hid, "confirmed")
    ex = next(i for i in group_investigations(s) if i.kind == "exploitability")
    assert ex.conclusion == "EXPLOITABLE"


def test_resolved_not_exploitable_earns_the_evidence_checklist():
    # Resolved exploitability: per-CVE evidence only (no global SSH checklist on every card).
    s = _state()
    # Generic refute objectives MUST NOT appear on the CVE card.
    s.investigation.objectives.add(Objective(name="refute:not_exploitable:ssh_agent_forwarding_enabled"))
    # CVE-named refute objective MAY appear.
    s.investigation.objectives.add(
        Objective(name="refute:not_exploitable:version_check_CVE-2021-31166", satisfied=True))
    hid = s.investigation.hypotheses.add_hypothesis(
        label="exploitability_of:verify:CVE-2021-31166", created_by="rule",
        likelihoods={"exploitable": 0.2, "not_exploitable": 0.8})
    s.investigation.hypotheses.resolve(hid, "confirmed")
    ex = next(i for i in group_investigations(s) if i.kind == "exploitability")
    assert ex.conclusion == "NOT EXPLOITABLE"
    names = {e.name for e in ex.evidence}
    assert "CVE matched (CVE-2021-31166)" in names
    assert "version_check_CVE-2021-31166" in names
    assert "ssh_agent_forwarding_enabled" not in names


def test_identification_and_novel_investigations():
    s = _state()
    s.investigation.hypotheses.add_hypothesis(label="ai:identify_framework:ex.com:80",
                                              created_by="ai", likelihoods={"iis": 0.7, "nginx": 0.3})
    nh = s.investigation.hypotheses.add_hypothesis(label="ai:novel:cache_poisoning",
                                                   created_by="ai", likelihoods={"vuln": 0.4, "safe": 0.6})
    s.investigation.hypotheses.resolve(nh, "refuted")
    invs = {i.kind: i for i in group_investigations(s)}
    assert invs["identification"].question == "What technology is running on ex.com:80?"
    assert invs["identification"].conclusion == "LIKELY iis"
    assert invs["novel"].question == "Is cache poisoning possible?"
    assert invs["novel"].conclusion == "REFUTED"


def test_grouping_collapses_many_objectives_into_few_cards():
    s = ReasoningState(target="ex.com:80", scope=["ex.com"])
    s.investigation.objectives.add(Objective(name="verify:CVE-1"))
    for i in range(8):
        s.investigation.objectives.add(Objective(name=f"refute:not_exploitable:check_{i}"))
    # resolve the CVE's exploitability so the card earns its evidence checklist (the collapse view)
    hid = s.investigation.hypotheses.add_hypothesis(
        label="exploitability_of:verify:CVE-1", created_by="rule",
        likelihoods={"exploitable": 0.3, "not_exploitable": 0.7})
    s.investigation.hypotheses.resolve(hid, "confirmed")
    invs = group_investigations(s)
    # 9 raw objectives → 1 investigation card; generic refute checks NOT stapled
    assert len(invs) == 1 and invs[0].kind == "exploitability"
    names = {e.name for e in invs[0].evidence}
    assert "CVE matched (CVE-1)" in names
    assert not any(n.startswith("check_") for n in names)


def test_empty_state_yields_no_investigations():
    assert group_investigations(ReasoningState(target="ex.com:80", scope=["ex.com"])) == []


def test_to_dict_shape():
    s = _state()
    s.investigation.hypotheses.add_hypothesis(
        label="exploitability_of:verify:CVE-2021-31166", created_by="rule",
        likelihoods={"exploitable": 0.35, "not_exploitable": 0.65})
    d = group_investigations(s)[0].to_dict()
    assert set(d) >= {"question", "conclusion", "confidence", "gathered", "total_evidence", "evidence"}
    assert isinstance(d["evidence"], list) and "satisfied" in d["evidence"][0]
