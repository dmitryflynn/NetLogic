"""
Investigation grouping — the human-readable view over the reasoning state.

The raw objective list is how the ENGINE thinks (dozens of `refute:not_exploitable:x11_forwarding`,
`verify:CVE-…`, `identify_framework:…`). That's noise to a person: those aren't investigations, they
are pieces of EVIDENCE. This module regroups them into a handful of INVESTIGATIONS the way an analyst
reads them:

    Investigation:  "Can CVE-2023-38408 be exploited?"
      Evidence:      ✓ CVE matched   ○ vulnerable version range   ○ mitigation present
      Conclusion:    LIKELY NOT EXPLOITABLE   (confidence 0.65)

It is a PURE, deterministic derivation: it only reads the ReasoningState (objectives + hypotheses),
mutates nothing, and adds no new reasoning. Presentation only.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EvidenceItem:
    name: str
    satisfied: bool

    def to_dict(self) -> dict:
        return {"name": self.name, "satisfied": self.satisfied}


@dataclass(frozen=True)
class Investigation:
    question: str
    subject: str
    kind: str                      # "exploitability" | "identification" | "novel"
    conclusion: str
    confidence: float = 0.0
    evidence: list = field(default_factory=list)   # EvidenceItem
    adjudicated_by_ai: bool = False   # the AI made this call where the engine was blind
    rationale: str = ""               # the AI's one-line reasoning, if adjudicated

    @property
    def gathered(self) -> int:
        return sum(1 for e in self.evidence if e.satisfied)

    def to_dict(self) -> dict:
        return {"question": self.question, "subject": self.subject, "kind": self.kind,
                "conclusion": self.conclusion, "confidence": round(self.confidence, 3),
                "gathered": self.gathered, "total_evidence": len(self.evidence),
                "adjudicated_by_ai": self.adjudicated_by_ai, "rationale": self.rationale,
                "evidence": [e.to_dict() for e in self.evidence]}


def _leading(hyp) -> tuple[str, float]:
    post = hyp.normalized_posterior()
    if not post:
        return ("", 0.0)
    name, mass = max(post.items(), key=lambda kv: kv[1])
    return (name, mass)


def _hyp_by_label(hyps, label: str):
    return next((h for h in hyps if h.label == label), None)


def _cve_description(state, cve: str) -> str:
    for n in state.world.graph.nodes("cve"):
        if n.key.lower() == cve.lower() or n.label.lower() == cve.lower():
            obs = next((str(o.evidence) for o in n.observations() if o.evidence), "")
            return obs[:160]
    return ""


def group_investigations(state) -> list[Investigation]:
    """Regroup the reasoning state's objectives + hypotheses into analyst-readable investigations."""
    objectives = state.investigation.objectives.all()
    hyps = state.investigation.hypotheses.all()
    investigations: list[Investigation] = []

    # ── Exploitability: one investigation per verified CVE, "Can CVE-X be exploited?" ──
    # The refute:not_exploitable:* objectives are the generic exploitability checks (version range,
    # reachability, patch level, mitigation) — shown as this investigation's evidence checklist.
    refute_evidence = [EvidenceItem(o.name.split(":", 2)[-1], o.satisfied)
                       for o in objectives if o.name.startswith("refute:not_exploitable:")]
    for o in objectives:
        if not o.name.startswith("verify:"):
            continue
        cve = o.name.split(":", 1)[1]
        exploit_hyp = _hyp_by_label(hyps, f"exploitability_of:{o.name}")
        lead, mass = _leading(exploit_hyp) if exploit_hyp else ("", 0.0)
        status = exploit_hyp.status if exploit_hyp else "active"
        # HONESTY: a CVE from a version/banner match is only ever a *lead*. It earns a real
        # conclusion ONLY when its exploitability hypothesis was actually resolved (confirmed/
        # refuted) by the engine or an active check. While it sits at its prior (status
        # "active") the engine has verified NOTHING — reporting "likely not exploitable" there
        # is false confidence (the 0.65 is just the prior), so we report it as UNVERIFIED and
        # do not staple the unrelated global refute checklist onto it.
        verified = status in ("confirmed", "refuted")
        if status == "confirmed":
            conclusion = "EXPLOITABLE" if lead == "exploitable" else "NOT EXPLOITABLE"
        elif status == "refuted":
            conclusion = "NOT EXPLOITABLE"
        elif lead == "exploitable" and mass >= 0.5:
            conclusion = "POSSIBLY EXPLOITABLE"
        else:
            conclusion = "UNVERIFIED"
        desc = _cve_description(state, cve)
        adjudicated = bool(getattr(exploit_hyp, "ai_adjudicated", False)) if exploit_hyp else False
        rationale = str(getattr(exploit_hyp, "ai_rationale", "")) if adjudicated else ""
        # Per-CVE evidence only — never staple the GLOBAL refute:* checklist onto
        # every card (that made Apache CVEs show "ssh_agent_forwarding_enabled").
        cve_l = cve.lower()
        per_cve_refute = [
            e for e in refute_evidence
            if cve_l in e.name.lower()
            or cve_l.replace("-", "") in e.name.lower().replace("-", "")
        ]
        if verified or conclusion == "POSSIBLY EXPLOITABLE":
            evidence = [EvidenceItem(f"CVE matched ({cve})", o.satisfied)]
            evidence.extend(per_cve_refute)
            if status == "refuted":
                label = "exploitability hypothesis refuted"
                if rationale:
                    label = f"{label} — {rationale[:140]}"
                evidence.append(EvidenceItem(label, True))
            elif status == "confirmed" and lead == "exploitable":
                evidence.append(EvidenceItem("exploitability hypothesis confirmed", True))
        else:
            # Honest: this is usually a deliberate ceiling, not "the engine is weak".
            # Coarse banners (IIS/10.0) cannot prove patch state; many RCE/UAF checks
            # (http.sys) are crash/DoS probes the core refuses to auto-run.
            evidence = [
                EvidenceItem(f"CVE matched from version banner ({cve})", o.satisfied),
                EvidenceItem(
                    "no tool proof yet — enable AI Investigation Agent to verify; "
                    "crash-class http.sys probes need allow_crash_probes",
                    False,
                ),
            ]
        investigations.append(Investigation(
            question=f"Can {cve} be exploited?",
            subject=f"{cve} — {desc}" if desc else cve,
            kind="exploitability", conclusion=conclusion, confidence=mass, evidence=evidence,
            adjudicated_by_ai=adjudicated, rationale=rationale))

    # ── Identification: "What technology is running on X?" ──
    idents: dict[str, list] = {}
    for o in objectives:
        for pre in ("identify_framework:", "identify_service:"):
            if o.name.startswith(pre):
                idents.setdefault(o.name.split(":", 1)[1], []).append(o)
    for subject, objs in idents.items():
        fw = _hyp_by_label(hyps, f"framework_of:identify_framework:{subject}") \
            or _hyp_by_label(hyps, f"ai:identify_framework:{subject}")
        lead, mass = _leading(fw) if fw else ("", 0.0)
        status = fw.status if fw else "active"
        if status == "confirmed" and lead:
            conclusion = f"CONFIRMED: {lead}"
        elif lead:
            conclusion = f"LIKELY {lead}"
        else:
            conclusion = "INVESTIGATING"
        investigations.append(Investigation(
            question=f"What technology is running on {subject}?",
            subject=subject, kind="identification", conclusion=conclusion, confidence=mass,
            evidence=[EvidenceItem(o.name.split(":", 1)[0], o.satisfied) for o in objs]))

    # ── Novel vulnerabilities: "Is <X> possible?" ──
    for o in objectives:
        if not o.name.startswith("novel:"):
            continue
        vuln = o.name.split(":", 1)[1]
        nh = _hyp_by_label(hyps, f"ai:novel:{vuln}")
        status = nh.status if nh else "active"
        conclusion = {"confirmed": "CONFIRMED", "refuted": "REFUTED"}.get(status, "INVESTIGATING")
        _, mass = _leading(nh) if nh else ("", 0.0)
        investigations.append(Investigation(
            question=f"Is {vuln.replace('_', ' ')} possible?",
            subject=vuln, kind="novel", conclusion=conclusion, confidence=mass,
            evidence=[EvidenceItem(f"investigate {vuln}", o.satisfied)]))

    return investigations
