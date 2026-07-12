"""Export a HackerOne-oriented markdown report from scan artifacts.

Does not submit anywhere — produces paste-ready report bodies for authorized
programs only. Pulls agent findings, PoCs, readiness scores, and investigations.
"""
from __future__ import annotations

from typing import Any


def _md_escape(s: str) -> str:
    return (s or "").replace("\r\n", "\n").strip()


def build_hackerone_markdown(art: dict, *, target: str = "") -> str:
    """Build a multi-finding HackerOne-style markdown report from engine art/JSON."""
    host = art.get("host") or art.get("host_result") or {}
    if isinstance(host, dict):
        tgt = target or host.get("target") or host.get("hostname") or host.get("ip") or "target"
        ip = host.get("ip") or ""
    else:
        tgt = target or "target"
        ip = ""

    agent = art.get("ai_agent") or {}
    findings = list(agent.get("findings") or [])
    pocs = list(agent.get("pocs") or [])
    readiness = agent.get("readiness") or {}
    invs = art.get("investigations") or []
    fusion = art.get("fusion") or {}
    confirmed_fusion = fusion.get("confirmed") or []

    # Prefer confirmed agent findings; fall back to fusion confirmed subjects
    confirmed = [f for f in findings if str(f.get("status") or "").lower() == "confirmed"]
    leads = [f for f in findings if str(f.get("status") or "").lower() != "confirmed"]

    lines: list[str] = []
    lines.append(f"# Security findings — `{tgt}`")
    lines.append("")
    lines.append("**Authorization:** Authorized assessment only. Do not use against systems without permission.")
    lines.append("")
    if ip:
        lines.append(f"- **Target:** `{tgt}` (`{ip}`)")
    else:
        lines.append(f"- **Target:** `{tgt}`")
    if readiness:
        lines.append(
            f"- **Submit readiness:** {readiness.get('ready_count', 0)}/"
            f"{readiness.get('total', 0)} confirmed findings scored ready"
        )
    lines.append(f"- **Agent confirmed:** {len(confirmed)} · **leads:** {len(leads)}")
    lines.append(f"- **Fusion confirmed subjects:** {len(confirmed_fusion)}")
    lines.append("")

    # Ready findings first
    ready_ids = set()
    for r in (readiness.get("reports") or []):
        if r.get("ready"):
            ready_ids.add(str(r.get("finding_id") or ""))

    def _poc_for(fid: str) -> dict | None:
        for p in pocs:
            if str(p.get("finding_id") or "") == fid:
                return p
        for f in findings:
            if str(f.get("id") or "") == fid and isinstance(f.get("poc"), dict):
                return {
                    "curl": f["poc"].get("curl"),
                    "expected": f["poc"].get("expected"),
                    "observation_id": f["poc"].get("observation_id"),
                }
        return None

    sections = confirmed or findings
    if not sections and confirmed_fusion:
        lines.append("## Fusion-confirmed subjects")
        lines.append("")
        for row in confirmed_fusion[:30]:
            if isinstance(row, dict):
                lines.append(f"- `{row.get('subject')}` — {row.get('rationale') or row.get('decision')}")
            else:
                lines.append(f"- `{row}`")
        lines.append("")
    elif not sections:
        lines.append("_No agent findings to export. Run with `--agent-depth` / `--ai-agent` for tool-backed items._")
        lines.append("")

    for i, f in enumerate(sections, 1):
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id") or f"finding-{i}")
        title = _md_escape(str(f.get("title") or fid))
        sev = f.get("suggested_severity") or f.get("severity") or "medium"
        status = f.get("status") or "lead"
        ready = fid in ready_ids or (
            status == "confirmed" and bool(f.get("poc") or _poc_for(fid))
        )
        lines.append(f"## {i}. {title}")
        lines.append("")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| ID | `{fid}` |")
        lines.append(f"| Severity (suggested) | **{str(sev).upper()}** |")
        lines.append(f"| Status | `{status}` |")
        lines.append(f"| H1-ready | {'yes' if ready else 'no — see checklist'} |")
        lines.append("")
        rationale = _md_escape(str(f.get("rationale") or ""))
        if rationale:
            lines.append("### Summary")
            lines.append("")
            lines.append(rationale)
            lines.append("")
        refs = f.get("evidence_refs") or []
        if refs:
            lines.append("### Evidence")
            lines.append("")
            lines.append("Observation ids: " + ", ".join(f"`{r}`" for r in refs[:12]))
            lines.append("")
        poc = _poc_for(fid)
        lines.append("### Steps to reproduce")
        lines.append("")
        if poc and poc.get("curl"):
            lines.append("```bash")
            lines.append(str(poc["curl"]))
            lines.append("```")
            lines.append("")
            if poc.get("expected"):
                lines.append(f"**Expected / vulnerable signal:** {poc['expected']}")
                lines.append("")
            if poc.get("observation_id"):
                lines.append(f"_Source observation: `{poc['observation_id']}`_")
                lines.append("")
        else:
            lines.append("_No `record_poc` attached — re-run agent turn with `record_poc` after the proving tool._")
            lines.append("")
        lines.append("### Impact")
        lines.append("")
        lines.append(
            f"Suggested severity **{sev}** based on NetLogic H1 rubric. "
            "Validate business impact for the program before submission."
        )
        lines.append("")
        lines.append("---")
        lines.append("")

    # Investigations appendix
    exploitable = [i for i in invs if isinstance(i, dict) and i.get("conclusion") == "EXPLOITABLE"]
    if exploitable:
        lines.append("## Investigation board (EXPLOITABLE)")
        lines.append("")
        for inv in exploitable[:20]:
            lines.append(f"- **{inv.get('question')}** — {inv.get('rationale') or ''}")
        lines.append("")

    lines.append("## Operator notes")
    lines.append("")
    lines.append("- Confirm asset is **in program scope** before filing.")
    lines.append("- Prefer one clear finding per report; do not file tech inventory.")
    lines.append("- Attach raw JSON observation if program allows supporting material.")
    lines.append("")
    return "\n".join(lines)


def write_hackerone_report(art: dict, path: str, *, target: str = "") -> str:
    md = build_hackerone_markdown(art, target=target)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(md)
    return path
