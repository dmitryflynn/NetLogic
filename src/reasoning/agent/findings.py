"""Merge agent findings into scan artifacts / investigation-friendly structures."""
from __future__ import annotations

from typing import Any


def agent_result_to_art(result) -> dict:
    """Serialize InvestigationAgent result for art[] / SSE."""
    d = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    return {
        "findings": d.get("findings") or [],
        "chains": d.get("chains") or [],
        "turns": d.get("turns") or [],
        "observations": d.get("observations") or [],
        "pocs": d.get("pocs") or [],
        "readiness": d.get("readiness"),
        "confirmed": d.get("confirmed") or 0,
        "leads": d.get("leads") or 0,
        "steps_used": d.get("steps_used") or 0,
        "requests_used": d.get("requests_used") or 0,
        "stopped_reason": d.get("stopped_reason") or "",
        "surface": d.get("surface") or {},
    }


def merge_agent_into_investigations(investigations: list[dict], agent_art: dict | None) -> list[dict]:
    """Upgrade investigation cards when the agent confirmed matching CVEs/findings.

    Pure function: returns a new list. Does not drop existing cards.
    """
    if not agent_art:
        return investigations
    from src.ip_scope import normalize_finding_id  # noqa: PLC0415

    findings = agent_art.get("findings") or []
    # Dedupe by canonical id first (model often re-asserts ssdp 4 ways).
    by_id: dict[str, dict] = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        cid = normalize_finding_id(str(f.get("id") or ""), str(f.get("title") or ""))
        if not cid:
            continue
        prev = by_id.get(cid)
        if prev is None:
            by_id[cid] = dict(f, id=cid)
            continue
        # Prefer confirmed; merge evidence refs
        if f.get("status") == "confirmed":
            prev["status"] = "confirmed"
        refs = list(dict.fromkeys(
            list(prev.get("evidence_refs") or []) + list(f.get("evidence_refs") or [])
        ))[:12]
        prev["evidence_refs"] = refs
        if f.get("rationale") and len(str(f.get("rationale"))) > len(str(prev.get("rationale") or "")):
            prev["rationale"] = f.get("rationale")
        if f.get("title") and not prev.get("title"):
            prev["title"] = f.get("title")
    if not by_id:
        return investigations

    out: list[dict] = []
    for inv in investigations:
        inv = dict(inv)
        q = str(inv.get("question") or "")
        subj = str(inv.get("subject") or "")
        # Match CVE ids in question/subject
        matched = None
        for cid, f in by_id.items():
            if cid and (cid.upper() in q.upper() or cid.upper() in subj.upper()
                        or cid in q.lower() or cid in subj.lower()):
                matched = f
                break
        if matched and matched.get("status") == "confirmed":
            inv["conclusion"] = "EXPLOITABLE"
            inv["adjudicated_by_ai"] = True
            inv["rationale"] = matched.get("rationale") or matched.get("title") or inv.get("rationale")
            # Drop stale "no tool proof yet" placeholders — agent already proved it.
            evidence = []
            for e in (inv.get("evidence") or []):
                if not isinstance(e, dict):
                    continue
                name = str(e.get("name") or "").lower()
                if "no tool proof" in name or "enable ai investigation agent" in name:
                    continue
                evidence.append(e)
            evidence.append({
                "name": f"AI agent confirmed via tools ({', '.join(matched.get('evidence_refs') or [])})",
                "satisfied": True,
            })
            inv["evidence"] = evidence
            inv["gathered"] = sum(1 for e in evidence if e.get("satisfied"))
            inv["total_evidence"] = len(evidence)
        out.append(inv)

    # Add agent findings that aren't already investigation subjects (one card per canonical id)
    existing_text = " ".join(
        str(i.get("question") or "") + str(i.get("subject") or "") for i in out
    ).lower()
    for fid, f in by_id.items():
        title = str(f.get("title") or fid)
        # Skip pure inventory tech cards as "EXPLOITABLE" investigations
        if fid.startswith("tech_"):
            continue
        if fid and fid.lower() in existing_text:
            continue
        if title.lower() in existing_text:
            continue
        status = f.get("status") or "lead"
        out.append({
            "question": title if title.startswith("Can ") else f"Agent finding: {title}",
            "subject": fid or title,
            "kind": "agent",
            "conclusion": "EXPLOITABLE" if status == "confirmed" else "UNVERIFIED",
            "confidence": 0.8 if status == "confirmed" else 0.4,
            "adjudicated_by_ai": True,
            "rationale": f.get("rationale") or "",
            "evidence": [
                {"name": r, "satisfied": True}
                for r in (f.get("evidence_refs") or [])
            ] or [{"name": "agent assertion", "satisfied": status == "confirmed"}],
            "gathered": 1 if status == "confirmed" else 0,
            "total_evidence": 1,
        })
    return out


def fold_agent_into_state(state: Any, agent_art: dict) -> None:
    """Optional: push confirmed agent findings onto the evidence graph."""
    if state is None or not agent_art:
        return
    try:
        for f in agent_art.get("findings") or []:
            if not isinstance(f, dict) or f.get("status") != "confirmed":
                continue
            fid = str(f.get("id") or "agent")
            node = state.world.graph.upsert_node("finding", fid.lower(), label=str(f.get("title") or fid)[:120])
            state.world.graph.observe(
                node,
                kind="agent_proof",
                evidence=str(f.get("rationale") or f.get("title") or "")[:300],
                source="ai_agent",
            )
    except Exception:  # noqa: BLE001
        pass
