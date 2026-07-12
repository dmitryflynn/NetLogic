"""
NetLogic API — Job management endpoints.

REST surface:
  POST   /jobs              Start a new scan (returns job_id, status 202)
  GET    /jobs              List recent jobs
  GET    /jobs/{id}         Inspect a single job (status, progress, counts)
  GET    /jobs/{id}/stream  Server-Sent Events stream of live scan events
  POST   /jobs/{id}/cancel  Cancel a queued/running job
  DELETE /jobs/{id}         Remove a job from memory (cleanup)

All endpoints require a valid JWT Bearer token.  The org_id embedded in the
token scopes every operation: jobs created by one organisation are never
visible to another.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse

from api.auth.dependencies import require_org
from api.auth.rate_limit import jobs_limiter, jobs_control_limiter
from api.jobs.executor import submit_scan
from api.jobs.manager import ScanJob, job_manager
from api.middleware.audit import audit_log
from api.models.scan_request import ScanRequest

router = APIRouter(prefix="/jobs", tags=["jobs"])

# ── POST /jobs ───────────────────────────────────────────────────────────────


@router.post(
    "",
    status_code=202,
    summary="Start a new scan job",
    response_description="Job ID and initial status",
)
async def create_job(
    request: Request,
    body: ScanRequest,
    org_id: str = Depends(require_org),
) -> dict:
    """
    Kick off an async scan. Returns immediately with a `job_id`.
    The job is scoped to the caller's organisation.
    """
    if not jobs_limiter.allow(org_id):
        raise HTTPException(status_code=429, detail="Job submission rate limit exceeded.")
    job = job_manager.create(body, org_id=org_id)
    try:
        await submit_scan(job)
    except Exception:
        job.status = "failed"
        job.error = "Failed to submit scan job."
        job_manager.persist_job(job)
        raise
    audit_log("job_created", job_id=job.job_id, org_id=org_id, target=body.target)
    return _job_summary(job)


# ── GET /jobs ────────────────────────────────────────────────────────────────


@router.get(
    "",
    summary="List recent jobs",
    response_description="Array of job summaries, newest first",
)
async def list_jobs(
    limit: int = Query(default=20, ge=1, le=200, description="Max jobs to return"),
    org_id: str = Depends(require_org),
) -> list[dict]:
    """Return up to `limit` jobs for the caller's organisation, sorted newest-first."""
    return [_job_summary(j) for j in job_manager.list(limit=limit, org_id=org_id)]


# ── GET /jobs/history/{target} ───────────────────────────────────────────────

def _scan_metrics(job: ScanJob) -> dict:
    """Per-scan posture snapshot derived from the stored event stream: open ports,
    severity breakdown, and the set of CVE ids — enough to chart a trend and to
    diff one scan against another (resolved vs new findings)."""
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    cves: set[str] = set()
    ports: set[int] = set()
    for e in job.events:
        t = e.get("type")
        d = e.get("data") or {}
        if t == "port":
            p = d.get("port")
            if isinstance(p, int):
                ports.add(p)
        elif t == "vuln":
            cid = d.get("cve_id")
            if cid:
                cves.add(str(cid))
            s = str(d.get("severity") or "").lower()
            if s in sev:
                sev[s] += 1
    # Also count fusion-confirmed findings (probes, AI, adjudicated
    # results) which are NOT stored as individual "vuln" events.
    fusion_events = [e for e in job.events if e.get("type") == "fusion"]
    if fusion_events:
        data = fusion_events[-1].get("data") or {}
        for row in data.get("confirmed", []) + data.get("potential", []):
            imp = str(row.get("impact") or "").lower()
            if imp in sev:
                sev[imp] += 1
            sub = row.get("subject", "")
            if sub.startswith("CVE-"):
                cves.add(sub)
    return {
        "open_ports": sorted(ports),
        "severity": sev,
        "vuln_total": sum(sev.values()),
        "cves": sorted(cves),
    }


@router.get(
    "/history/{target}",
    summary="Scan history & posture timeline for one target",
    response_description="Chronological scans of the target with posture metrics",
)
async def target_history(
    target: str,
    org_id: str = Depends(require_org),
) -> dict:
    """Return every completed scan of `target` for the caller's org, oldest→newest,
    each with open-ports / severity / CVE-set so the dashboard can show progress
    over time and a before→after diff between consecutive scans."""
    jobs = [
        j for j in job_manager.list(limit=500, org_id=org_id)
        if j.config.target == target
    ]
    # Show completed first (chronological), then running/queued at the end
    jobs.sort(key=lambda j: (0 if j.status == "completed" else 1, j.completed_at or j.created_at))
    scans = []
    for j in jobs:
        m = _scan_metrics(j)
        scans.append({
            "job_id": j.job_id,
            "status": j.status,
            "progress": j.progress,
            "completed_at": j.completed_at,
            "created_at": j.created_at,
            **m,
        })
    return {"target": target, "scans": scans}


# ── GET /jobs/{id} ───────────────────────────────────────────────────────────


@router.get(
    "/{job_id}",
    summary="Get job status / results",
    response_description="Full job detail",
)
async def get_job(
    job_id: str,
    org_id: str = Depends(require_org),
) -> dict:
    """
    Returns the current job state including progress and result counts.
    Returns 404 if the job does not exist or belongs to a different organisation.
    """
    job = _get_or_404(job_id, org_id)
    return _job_detail(job)


# ── GET /jobs/{id}/stream ────────────────────────────────────────────────────


@router.get(
    "/{job_id}/stream",
    summary="Stream job events (SSE)",
    response_description="text/event-stream of events",
)
async def stream_job(
    job_id: str,
    org_id: str = Depends(require_org),
) -> StreamingResponse:
    """
    Opens an SSE connection for real-time updates.
    """
    if not jobs_control_limiter.allow(org_id):
        raise HTTPException(status_code=429, detail="Too many stream requests. Slow down.")
    job = _get_or_404(job_id, org_id)
    return StreamingResponse(
        _sse_generator(job),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── POST /jobs/{id}/cancel ───────────────────────────────────────────────────


@router.post(
    "/{job_id}/cancel",
    summary="Cancel a running job",
)
async def cancel_job(
    job_id: str,
    org_id: str = Depends(require_org),
) -> dict:
    """
    Request cancellation of a queued or running job.
    """
    if not jobs_control_limiter.allow(org_id):
        raise HTTPException(status_code=429, detail="Too many control requests. Slow down.")
    job = _get_or_404(job_id, org_id)
    if job.status in ("completed", "failed", "cancelled"):
        return {"job_id": job_id, "status": job.status, "cancelled": False,
                "detail": "Job already in terminal state."}

    job.status = "cancelled"
    job.completed_at = time.time()
    job.error = "Cancelled by user request."

    # Signal the scan thread to unwind at its next event emission. Without this
    # the scan would run to completion and overwrite the 'cancelled' status.
    job._stop_flag.set()

    job.push_event({"type": "error", "message": job.error})
    job.push_sentinel()

    job_manager.persist_job(job)
    audit_log("job_cancelled", job_id=job_id, org_id=org_id, target=job.config.target)

    return {"job_id": job_id, "status": job.status, "cancelled": True}


# ── DELETE /jobs/{id} ────────────────────────────────────────────────────────


@router.delete(
    "/{job_id}",
    summary="Delete a job (manual cleanup)",
    status_code=204,
)
async def delete_job(
    job_id: str,
    org_id: str = Depends(require_org),
):
    """
    Remove a job from the in-memory registry. If the job is running, it will be cancelled first.
    """
    if not jobs_control_limiter.allow(org_id):
        raise HTTPException(status_code=429, detail="Too many control requests. Slow down.")
    job = job_manager.get(job_id, org_id=org_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # If the job is still running, signal the scan thread to stop and close any
    # open SSE stream before we drop the job from the registry — otherwise the
    # scan thread keeps running and pushing events into an orphaned job.
    if job.status in ("queued", "running"):
        job._stop_flag.set()
        job.push_sentinel()

    job_manager.delete(job_id)
    return Response(status_code=204)


# ── Explore Beyond Known CVEs ──────────────────────────────────────────────────

from pydantic import BaseModel, Field  # noqa: E402


class ExploreBeyondIn(BaseModel):
    finding: str = Field(..., max_length=2000, description="The Beyond CVE finding text to elaborate on")


@router.post("/{job_id}/explore-beyond", summary="Elaborate on a Beyond Known CVEs finding")
async def explore_beyond(
    job_id: str,
    body: ExploreBeyondIn,
    request: Request,
    org_id: str = Depends(require_org),
) -> dict:
    """Ask the AI to deep-dive on one specific Beyond CVEs finding from a completed scan."""
    if not jobs_control_limiter.allow(org_id):
        raise HTTPException(status_code=429, detail="Too many explore requests. Slow down.")
    job = _get_or_404(job_id, org_id)
    if job.status != "completed":
        raise HTTPException(status_code=400, detail="Scan must be completed first.")

    from src.ai_analyst import config_for_org, analyze  # noqa: PLC0415

    cfg = config_for_org(org_id, role="ai").resolve()
    usable, reason = cfg.is_usable()
    if not usable:
        if not cfg.provider:
            reason = "No AI provider is configured. Go to Settings → AI to add an API key, then retry."
        return {"markdown": "", "error": reason}

    system = (
        "You are a senior security analyst doing a deep-dive on a specific finding "
        "from the 'Beyond Known CVEs' section of a previous scan report. "
        "Given the finding below, provide a detailed technical elaboration: "
        "explain the specific risk, how an attacker might exploit it, what conditions "
        "make it dangerous, what real-world precedents exist, and how to validate or "
        "confirm it. Be specific and actionable. Use markdown."
    )
    user = (
        f"Elaborate on this Beyond CVEs finding from the scan of `{job.config.target}`:\n\n"
        f"{body.finding}\n\n"
        "Provide a detailed analysis: risk assessment, exploitation scenario, "
        "validation steps, and remediation guidance. Be specific to this host and finding."
    )
    result = analyze({"_explore": f"{system}\n\n{user}"}, cfg)
    if result.error:
        return {"markdown": "", "error": result.error}
    return {"markdown": result.markdown}


# ── SSE event generator ───────────────────────────────────────────────────────


def _drain(job: ScanJob, idx: int):
    """Yield (sse_string, new_idx, terminal) for every event past absolute cursor `idx`.

    `idx` is an ABSOLUTE stream position (count of events the consumer has already
    seen), NOT an index into the current deque. The deque is capped (maxlen) and
    its left is evicted as new events arrive, so deque[i] holds absolute index
    (base + i) where base = job._total_events - len(job.events). Slicing the deque
    by a raw absolute index — as the previous implementation did — silently skips
    every event once the stream passes EVENT_CAP. Here we translate the absolute
    cursor into a deque offset, clamping to `base` if the consumer fell so far
    behind that earlier events were already evicted (unavoidable loss, but never a
    skip/dup/cursor-corruption of the events that ARE still buffered).
    """
    snapshot = list(job.events)
    base = job._total_events - len(snapshot)
    start = idx - base
    if start < 0:
        # Consumer fell >EVENT_CAP behind; those events are gone. Resume from the
        # oldest event still buffered without corrupting the cursor.
        start = 0
        idx = base
    out = []
    for event in snapshot[start:]:
        idx += 1
        out.append((f"data: {json.dumps(event, default=str)}\n\n", idx,
                    event.get("type") in ("done", "error")))
    return out


async def _sse_generator(job: ScanJob) -> AsyncGenerator[str, None]:
    """
    Resilient SSE generator with cursor-based replay and non-blocking queue.

    The cursor `idx` is an absolute stream position (see _drain). job.events is a
    capped deque; we translate the cursor through job._total_events so eviction of
    old events while we stream cannot make us skip or duplicate live events.
    """
    idx = 0
    # Max iterations waiting for _queue to be initialised (covers the rare race
    # between create_job returning and submit_scan setting job._queue).
    _queue_wait_retries = 0
    _QUEUE_WAIT_MAX = 150  # 30 s at 0.2 s per sleep

    while True:
        # 1. Drain available events from history (replay/catch-up).
        for sse, idx, terminal in _drain(job, idx):
            yield sse
            if terminal:
                return  # terminal event delivered → stream is done.

        # 2. Check if job finished while we were processing history.
        if job.status in ("completed", "failed", "cancelled"):
            # Final catch-up for any events added after the last drain.
            for sse, idx, terminal in _drain(job, idx):
                yield sse
                if terminal:
                    return
            return

        # 3. Wait for the SSE queue to be initialised (set by submit_scan).
        if job._queue is None:
            _queue_wait_retries += 1
            if _queue_wait_retries > _QUEUE_WAIT_MAX:
                # submit_scan never ran or the job was never dispatched; bail out.
                yield 'data: {"type":"error","message":"Stream initialisation timeout."}\n\n'
                return
            await asyncio.sleep(0.2)
            continue

        _queue_wait_retries = 0  # reset counter once queue is alive

        try:
            # Keep-alive ping every 30 s to prevent proxy timeouts.
            signal = await asyncio.wait_for(job._queue.get(), timeout=30.0)
        except asyncio.TimeoutError:
            yield 'data: {"type":"ping"}\n\n'
            continue
        except asyncio.CancelledError:
            return  # Client disconnected.

        # 4. Sentinel received: scan thread is finished.
        if signal is None:
            # One final pass to ensure zero data loss.
            for sse, idx, terminal in _drain(job, idx):
                yield sse
                if terminal:
                    return
            return

        # 5. Signal received: loop back to Phase 1 to drain the new event(s).


# ── Shared helpers ────────────────────────────────────────────────────────────


def _get_or_404(job_id: str, org_id: str = "") -> ScanJob:
    job = job_manager.get(job_id, org_id=org_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    return job


def _job_summary(job: ScanJob) -> dict:
    # Calculate counts from events
    ports_count = sum(1 for e in job.events if e.get("type") == "port")
    vulns_count = sum(1 for e in job.events if e.get("type") == "vuln")

    # Fusion summary is the authoritative count — it reflects the
    # gate's adjudicated view (confirmed + potential after filtering).
    # Raw "vuln" events include duplicates and discarded findings that
    # the gate already processed, so we trust fusion when available.
    fusion_events = [e for e in job.events if e.get("type") == "fusion"]
    if fusion_events:
        last = fusion_events[-1]
        summary = (last.get("data") or {}).get("summary") or {}
        confirmed = summary.get("confirmed") or 0
        potential = summary.get("potential") or 0
        vulns_count = confirmed + potential
    return {
        "job_id": job.job_id,
        "org_id": job.org_id,
        "status": job.status,
        "progress": job.progress,
        "target": job.config.target,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "result_counts": {
            "ports": ports_count,
            "vulnerabilities": vulns_count,
        },
        "error": job.error,
    }


def _job_detail(job: ScanJob) -> dict:
    detail = _job_summary(job)
    detail["config"] = job.config.public_dump()
    # Always include event history (capped) so the Event log survives after the scan
    # finishes — and is available mid-run if SSE reconnects. UI uses this for the
    # post-scan "Event log" panel.
    # Cap for API payload size; deque may hold up to EVENT_CAP. Prefer newest events
    # so late agent turns remain visible when history is long.
    ev = list(job.events)
    detail["events"] = ev[-2000:] if len(ev) > 2000 else ev
    return detail


def _ts(ts: float | None) -> str:
    """Format a unix timestamp to a readable string."""
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


def _export_markdown(job: ScanJob) -> str:
    """Build a human-readable Markdown report from job events.
    Works for any job status (completed, failed, running, queued, cancelled)."""
    s = _job_summary(job)
    rc = s["result_counts"]
    cfg = getattr(job, "config", None)
    metrics = _scan_metrics(job)
    sev = metrics["severity"]
    total_vulns = sum(sev.values())
    lines: list[str] = []

    # ── Raw data (full JSON at top for programmatic use) ──────────────────
    detail = _job_detail(job)
    lines.append("```json")
    lines.append(json.dumps(detail, indent=2, default=str))
    lines.append("```")
    lines.append("")

    # ── Header ────────────────────────────────────────────────────────────
    lines.append(f"# Scan Report: {s['target']}")
    parts = [f"**Status:** {s['status']}"]
    if cfg:
        enabled = [k for k in ("do_tls", "do_headers", "do_stack", "do_dns",
                               "do_osint", "do_probe", "do_takeover", "do_ai")
                   if getattr(cfg, k, False)]
        extra = ", ".join(enabled) if enabled else "basic"
        parts.append(f"{cfg.ports}p · {cfg.timeout}s · {extra}")
    lines.append(" | ".join(parts))
    lines.append(f"Started {_ts(s['started_at'])} · Completed {_ts(s['completed_at'])}")
    if s.get("error"):
        lines.append(f"**Error:** {s['error']}")
    lines.append("")

    # ── Summary ───────────────────────────────────────────────────────────
    if rc["ports"] == 0 and total_vulns == 0 and s["status"] == "completed":
        lines.append("No open ports or vulnerabilities found — target appears clean.")
        lines.append("")
    else:
        summary_parts = [f"**Open ports:** {rc['ports']}"]
        if total_vulns:
            summary_parts.append(f"**Findings:** {total_vulns} ({', '.join(f'{sev[k]} {k}' for k in ('critical', 'high', 'medium', 'low') if sev.get(k))})")
        if rc.get("vulnerabilities"):
            summary_parts.append(f"**CVEs:** {rc['vulnerabilities']}")
        lines.append(" · ".join(summary_parts))
        lines.append("")

    # ── Open ports ────────────────────────────────────────────────────────
    port_events = [e for e in job.events if e.get("type") == "port"]
    if port_events:
        lines.append("### Open Ports")
        lines.append("")
        lines.append("| Port | Service | Product | Version | TLS |")
        lines.append("|------|---------|---------|---------|-----|")
        for e in port_events:
            d = e.get("data") or {}
            svc = d.get("service", "") or "—"
            prod = d.get("product", "") or "—"
            ver = d.get("version", "") or "—"
            tls = "✓" if d.get("tls") else "—"
            lines.append(f"| {d.get('port', '') or '—'} | {svc} | {prod} | {ver} | {tls} |")
        lines.append("")

    # ── Findings (unified confirmed/potential/discarded) ──────────────────
    fusion_events = [e for e in job.events if e.get("type") == "fusion"]
    if fusion_events:
        data = fusion_events[-1].get("data") or {}
        summary = data.get("summary") or {}
        confirmed = data.get("confirmed", [])
        potential = data.get("potential", [])
        discarded = data.get("discarded", [])

        all_findings = (
            [dict(row, _type="Confirmed") for row in confirmed]
            + [dict(row, _type="Potential") for row in potential]
            + [dict(row, _type="Discarded") for row in discarded]
        )
        if all_findings:
            lines.append("### Findings")
            lines.append("")
            has_rationale = any(row.get("rationale") for row in discarded)
            headers = "| Type | Subject | Port | Impact"
            sep    = "|------|---------|------|--------"
            if has_rationale:
                headers += " | Rationale"
                sep    += "|-----------"
            headers += " |"
            sep    += " |"
            lines.append(headers)
            lines.append(sep)
            for row in all_findings:
                r = [f"| {row.get('_type', '')} | {row.get('subject', '')} | {row.get('port', '') or '—'} | {row.get('impact', '')}"]
                if has_rationale:
                    r.append(f" {row.get('rationale', '') or '—'}")
                r.append(" |")
                lines.append("".join(r))
            lines.append("")
        lines.append(f"*{summary.get('signals', 0)} signals · {summary.get('confirmed', 0)} confirmed · "
                     f"{summary.get('potential', 0)} potential · {summary.get('discarded', 0)} discarded · "
                     f"{summary.get('ai_adjudicated', 0)} AI-adjudicated*")
        lines.append("")

    # ── CVEs ──────────────────────────────────────────────────────────────
    vuln_events = [e for e in job.events if e.get("type") == "vuln"]
    if vuln_events:
        lines.append("### CVEs")
        lines.append("")
        lines.append("| CVE | Port | Severity | CVSS | EPSS | KEV |")
        lines.append("|-----|------|----------|------|------|-----|")
        for e in vuln_events:
            d = e.get("data") or {}
            epss = d.get("epss")
            epss_s = f"{float(epss)*100:.1f}%" if epss else "—"
            lines.append(f"| {d.get('cve_id', '') or '—'} | {d.get('port', '') or '—'} | "
                         f"{d.get('severity', '') or '—'} | {d.get('cvss', '') or '—'} | "
                         f"{epss_s} | {'✓' if d.get('kev') else '—'} |")
        lines.append("")

    # ── AI Analysis ──────────────────────────────────────────────────────
    ai_events = [e for e in job.events if e.get("type") == "ai"]
    if ai_events:
        last_ai = ai_events[-1].get("data") or {}
        md = last_ai.get("markdown")
        if md:
            lines.append("## AI Analysis")
            lines.append("")
            lines.append(md)
            lines.append("")

    # ── Scan Config (compact, at the end) ────────────────────────────────
    if cfg:
        flags = [k for k in ("do_tls", "do_headers", "do_stack", "do_dns", "do_osint",
                              "do_probe", "do_takeover", "do_ai")
                 if getattr(cfg, k, False)]
        enabled_str = ", ".join(flags) if flags else "basic"
        lines.append(f"*Config: `{cfg.target}` · {cfg.ports} ports · {cfg.timeout}s · "
                     f"{cfg.threads} threads · min CVSS {cfg.min_cvss} · {enabled_str}*")
        lines.append("")

    return "\n".join(lines)


@router.get("/{job_id}/export", summary="Export scan results")
async def export_job(
    job_id: str,
    request: Request,
    format: str = Query(default="json", pattern="^(json|md|raw)$"),
    org_id: str = Depends(require_org),
) -> Response:
    """Download scan results as JSON or Markdown. Works for any job status."""
    job = _get_or_404(job_id, org_id)
    target_slug = re.sub(r"[^a-zA-Z0-9_-]", "_", job.config.target)
    if format == "md":
        body = _export_markdown(job)
        return Response(
            content=body,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="scan_{target_slug}.md"'},
        )
    if format == "raw":
        events_list = list(job.events)
        body = json.dumps({
            "job_id": job.job_id,
            "status": job.status,
            "target": job.config.target if job.config else "",
            "config": job.config.public_dump() if job.config else None,
            "events": events_list,
            "event_count": len(events_list),
        }, indent=2, default=str)
        return Response(
            content=body,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan_{target_slug}_raw.json"'},
        )
    detail = _job_detail(job)
    return Response(
        content=json.dumps(detail, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="scan_{target_slug}.json"'},
    )
