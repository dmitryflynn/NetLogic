"""Per-target scan history / posture timeline endpoint."""
import asyncio
import uuid

from api.jobs.manager import ScanJob
from api.models.scan_request import ScanRequest
from api.routes import jobs as jobs_route


def _job(target, cves, ports, org="org-a", status="completed", completed=1.0):
    j = ScanJob(job_id=str(uuid.uuid4()), config=ScanRequest(target=target, ports="quick"), org_id=org)
    j.status = status
    j.completed_at = completed
    for p in ports:
        j.events.append({"type": "port", "data": {"port": p}})
    for cid, sev in cves:
        j.events.append({"type": "vuln", "data": {"cve_id": cid, "severity": sev, "port": 80}})
    return j


def test_scan_metrics_aggregates_severity_ports_and_cves():
    j = _job("x.com", [("CVE-1", "CRITICAL"), ("CVE-2", "high"), ("CVE-1", "critical")], [80, 443, 80])
    m = jobs_route._scan_metrics(j)
    assert m["open_ports"] == [80, 443]                    # de-duped, sorted
    assert m["severity"] == {"critical": 2, "high": 1, "medium": 0, "low": 0}
    assert m["vuln_total"] == 3
    assert m["cves"] == ["CVE-1", "CVE-2"]                  # de-duped, sorted


def test_history_is_chronological_and_org_scoped(monkeypatch):
    older = _job("acme.com", [("CVE-1", "critical"), ("CVE-2", "high")], [80, 443, 22], completed=100.0)
    newer = _job("acme.com", [("CVE-2", "high")], [80, 443], completed=200.0)   # CVE-1 + port 22 resolved
    other_target = _job("other.com", [("CVE-9", "critical")], [80], completed=150.0)
    other_org = _job("acme.com", [("CVE-X", "critical")], [80], org="org-b", completed=300.0)
    running = _job("acme.com", [], [80], status="running", completed=None)

    monkeypatch.setattr(jobs_route.job_manager, "list",
                        lambda limit=500, org_id="": [j for j in [newer, older, other_target, other_org, running] if j.org_id == (org_id or j.org_id)])

    res = asyncio.run(jobs_route.target_history("acme.com", org_id="org-a"))
    assert res["target"] == "acme.com"
    scans = res["scans"]
    # only acme.com + org-a → completed first (chronological), then running/queued
    assert [s["job_id"] for s in scans] == [older.job_id, newer.job_id, running.job_id]
    assert scans[0]["severity"]["critical"] == 1 and scans[1]["severity"]["critical"] == 0
    assert scans[0]["open_ports"] == [22, 80, 443] and scans[1]["open_ports"] == [80, 443]
    # running scan included with its status
    assert scans[2]["status"] == "running"
    # the diff the UI computes: CVE-1 resolved, port 22 closed, between older→newer
    assert "CVE-1" in scans[0]["cves"] and "CVE-1" not in scans[1]["cves"]


def test_history_empty_for_unscanned_target(monkeypatch):
    monkeypatch.setattr(jobs_route.job_manager, "list", lambda limit=500, org_id="": [])
    res = asyncio.run(jobs_route.target_history("never.com", org_id="org-a"))
    assert res == {"target": "never.com", "scans": []}
