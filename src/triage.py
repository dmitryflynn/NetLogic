"""
Deterministic finding triage — lead with findings that have real evidence, not
banner→CVE pattern matches.

Version/banner pattern-matched CVEs are NEVER "attention" findings: patch level
cannot be confirmed from a version string (distros backport fixes). Those leads
are bucketed as noise with an explicit rationale so the report can show them as
filtered, not as vulnerabilities.

What *does* reach Top Findings (attention):
  • Web/SaaS / exposed-file findings (content-validated)
  • (Probe-confirmed CVEs are promoted via fusion, not this correlator path)

Pure correlator CVE ranking is retained only to order the filtered-lead list.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class TriageItem:
    cve: str
    port: int
    service: str
    cvss: float
    cvss_vector: str
    cwe: str
    epss: float
    kev: bool
    exploit_available: bool
    reachable: str            # "open" | "forbidden" | "unknown"
    priority: str             # "P1".."P5"
    bucket: str               # "attention" | "noise"
    rationale: str
    kind: str = "cve"         # "cve" | "web" (SaaS / exposed-file finding)
    title: str = ""           # display label for non-CVE items (e.g. "Clerk: <instance>")

    def to_dict(self) -> dict:
        return {"cve": self.cve, "port": self.port, "service": self.service,
                "cvss": self.cvss, "cvss_vector": self.cvss_vector, "cwe": self.cwe,
                "epss": self.epss, "kev": self.kev, "exploit_available": self.exploit_available,
                "reachable": self.reachable, "priority": self.priority, "bucket": self.bucket,
                "rationale": self.rationale, "kind": self.kind, "title": self.title}


@dataclass
class TriageResult:
    attention: list = field(default_factory=list)   # TriageItem, worst-first
    noise: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "attention": [i.to_dict() for i in self.attention],
            "noise": [i.to_dict() for i in self.noise],
            "counts": {
                "attention": len(self.attention),
                "noise": len(self.noise),
                "kev": sum(1 for i in self.attention + self.noise if i.kev),
                "total": len(self.attention) + len(self.noise),
            },
        }


def _reachability_map(service_exploitability) -> dict[int, str]:
    """port -> 'open'/'forbidden' from the http_auth_state exploitability attribute (if enumerated)."""
    out: dict[int, str] = {}
    attrs = getattr(service_exploitability, "attributes", None) or []
    for a in attrs:
        if getattr(a, "attribute", "") == "http_auth_state":
            val = str(getattr(a, "value", "")).lower()
            if val in ("open", "forbidden"):
                out[getattr(a, "port", 0)] = val
    return out


def _priority(cvss: float, epss: float, kev: bool, exploit: bool, reachable: str) -> str:
    reach = reachable == "open"
    unreach = reachable == "forbidden"
    if kev:
        return "P1"
    if exploit and reach and cvss >= 9.0:
        return "P1"
    if epss >= 0.5 or (cvss >= 9.0 and not unreach) or exploit:
        return "P2"
    if cvss >= 7.0:
        return "P3"
    if cvss >= 4.0:
        return "P4"
    return "P5"


def _bucket(priority: str, reachable: str) -> str:
    if priority in ("P1", "P2"):
        return "attention"
    if priority == "P3" and reachable == "open":
        return "attention"
    return "noise"


def _rationale(cvss: float, epss: float, kev: bool, exploit: bool, reachable: str) -> str:
    # All correlator CVEs are pattern/version leads — never findings.
    if kev:
        return "version pattern + CISA KEV catalog hit — not a finding until actively verified"
    if exploit and reachable == "open":
        return "version pattern + public exploit noted — not a finding until actively verified"
    if epss >= 0.5:
        return f"version pattern + high EPSS ({epss * 100:.0f}%) — not a finding until actively verified"
    if reachable == "forbidden":
        return "version pattern only; endpoint access-controlled — filtered"
    if cvss >= 9.0:
        return "version/banner pattern only (high CVSS catalog) — not a finding until actively verified"
    return "version/banner pattern match only — not a finding until actively verified"


def triage(vuln_matches, service_exploitability=None, web_fingerprint=None) -> TriageResult:
    """Rank + bucket every matched CVE + WS6 web/SaaS finding. De-dup CVEs by id (keep highest priority).

    `vuln_matches`: list of VulnMatch (dataclass or dict). `service_exploitability`: ServiceEnumResult
    (or None). `web_fingerprint`: WebFingerprint dict/obj with `saas`/`exposed_files` (or None).
    Pure + reproducible."""
    reach = _reachability_map(service_exploitability)
    _ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "P5": 4}

    best: dict[str, TriageItem] = {}          # cve id -> best (lowest P) instance
    for vm in vuln_matches or []:
        port = _get(vm, "port", 0)
        service = _get(vm, "service", "")
        for c in _get(vm, "cves", []) or []:
            cid = _get(c, "id", "")
            if not cid:
                continue
            cvss = float(_get(c, "cvss_score", 0.0) or 0.0)
            epss = float(_get(c, "epss", 0.0) or 0.0)
            kev = bool(_get(c, "kev", False))
            exploit = bool(_get(c, "exploit_available", False) or _get(c, "has_public_exploit", False))
            reachable = reach.get(port, "unknown")
            # Pattern-matched correlator CVEs: never "attention" findings.
            pr = _priority(cvss, epss, kev, exploit, reachable)
            item = TriageItem(
                cve=cid, port=port, service=service, cvss=cvss,
                cvss_vector=str(_get(c, "vector", "")), cwe=str(_get(c, "cwe", "")),
                epss=epss, kev=kev, exploit_available=exploit, reachable=reachable,
                priority=pr, bucket="noise",
                rationale=_rationale(cvss, epss, kev, exploit, reachable))
            prev = best.get(cid)
            if prev is None or _ORDER[pr] < _ORDER[prev.priority]:
                best[cid] = item

    items = list(best.values())
    web = _web_items(web_fingerprint)      # content-validated SaaS / exposed files → real findings
    # Sort: web attention first by priority, then version-leads (noise) by priority/KEV/EPSS.
    items = web + items
    items.sort(key=lambda i: (
        0 if i.bucket == "attention" else 1,
        _ORDER.get(i.priority, 5), not i.kev, -i.epss, -i.cvss))
    res = TriageResult()
    for i in items:
        (res.attention if i.bucket == "attention" else res.noise).append(i)
    return res


_SEV_TO_PRIORITY = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4", "INFO": "P5"}


def _web_items(web_fingerprint) -> list:
    """Map WS6 web-app findings (third-party SaaS + content-validated exposed files) into TriageItems
    so the modern-web surface leads the Top Findings hero alongside CVEs. Severity → P1..P5;
    CRITICAL/HIGH/MEDIUM → attention, LOW/INFO → noise (don't cry wolf on public keys)."""
    out: list = []
    if not web_fingerprint:
        return out
    for h in _get(web_fingerprint, "saas", []) or []:
        sev = str(_get(h, "severity", "INFO")).upper()
        pr = _SEV_TO_PRIORITY.get(sev, "P5")
        svc = str(_get(h, "service", ""))
        ev = str(_get(h, "evidence", ""))
        out.append(TriageItem(
            cve="", port=0, service=svc, cvss=0.0, cvss_vector="", cwe="", epss=0.0, kev=False,
            exploit_available=False, reachable="unknown", priority=pr,
            bucket=("attention" if sev in ("CRITICAL", "HIGH", "MEDIUM") else "noise"),
            rationale=str(_get(h, "detail", "")), kind="web",
            title=f"{svc}: {ev}" if ev else svc))
    for path in _get(web_fingerprint, "exposed_files", []) or []:
        out.append(TriageItem(
            cve="", port=0, service="web", cvss=0.0, cvss_vector="", cwe="", epss=0.0, kev=False,
            exploit_available=False, reachable="unknown", priority="P2", bucket="attention",
            rationale="publicly accessible with expected file content (content-validated, not a soft-404)",
            kind="web", title=f"exposed file: {path}"))
    return out


def _get(obj, name, default=None):
    """Read a field from a dataclass OR a dict (the report serialises both shapes)."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)
