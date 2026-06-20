"""
Fusion layer — HTTP cassette record/replay harness (Vulhub + clean fixtures).

The benchmark must run the pipeline against RAW RECORDED HTTP TRAFFIC, not hand-coded
mock servers. A "cassette" is a JSON recording of a target's HTTP interactions plus
ground-truth labels. The CassettePlayer replays it — including STATEFUL multi-request
sequences (request 1 yields a CSRF token / cookie, request 2 submits it) — so real
sensors execute against recorded reality.

Record real cassettes from Vulhub:
    docker compose -f vulhub/<cve>/docker-compose.yml up -d
    # drive the target through a recording proxy (mitmproxy/VCR) and save the flows
    # into the schema below (one "vulnerable" cassette + a "clean"/patched cassette).

Cassette schema (see src/fusion/data/cassettes/*.json):
  {
    "name": str, "label_source": "vulhub:CVE-... | clean",
    "target": {"host": str, "port": int},
    "exposure": {"reachability": "public|private|cloud|unknown", ...},
    "interactions": [{"request": {method,path,headers,body},
                      "response": {status,headers,body}}],
    "probes": [{"claim": str, "cvss": float, "kev": bool, "severity": str,
                "steps": [{method,path,headers,body,extract:{var:regex},success:regex}]}],
    "truth": [{"port": int, "claim": str, "is_real": bool, "severity": str}]
  }
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from src.fusion.sensors import HttpResponse, Wappalyzer
from src.fusion.signals import Signal

_CASSETTE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cassettes")


# ── Records ─────────────────────────────────────────────────────────────────────

@dataclass
class RecordedResponse:
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    cookies: dict = field(default_factory=dict)


@dataclass
class Cassette:
    name: str
    target: dict
    interactions: list
    probes: list = field(default_factory=list)
    cve_candidates: list = field(default_factory=list)   # version-matched leads → gray band
    truth: list = field(default_factory=list)
    exposure: dict = field(default_factory=lambda: {"reachability": "unknown"})
    label_source: str = ""

    @property
    def host(self) -> str:
        return self.target.get("host", "recorded-host")

    @property
    def port(self) -> int:
        return int(self.target.get("port", 80))


def load_cassette(path: str) -> Cassette:
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    return Cassette(
        name=d.get("name", os.path.basename(path)),
        target=d.get("target", {}),
        interactions=d.get("interactions", []),
        probes=d.get("probes", []),
        cve_candidates=d.get("cve_candidates", []),
        truth=d.get("truth", []),
        exposure=d.get("exposure", {"reachability": "unknown"}),
        label_source=d.get("label_source", ""),
    )


def load_cassettes(directory: Optional[str] = None) -> list[Cassette]:
    directory = directory or _CASSETTE_DIR
    out = []
    if not os.path.isdir(directory):
        return out
    for name in sorted(os.listdir(directory)):
        if name.endswith(".json"):
            try:
                out.append(load_cassette(os.path.join(directory, name)))
            except (OSError, json.JSONDecodeError):
                continue
    return out


# ── Replay (stateful) ───────────────────────────────────────────────────────────

def _parse_cookies(headers: dict) -> dict:
    cookies = {}
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            first = str(v).split(";", 1)[0]
            if "=" in first:
                name, val = first.split("=", 1)
                cookies[name.strip()] = val.strip()
    return cookies


class CassettePlayer:
    """Replays recorded interactions. Matches by (METHOD, path); repeated calls to the
    same key advance a cursor so a multi-step sequence returns its successive recorded
    responses (the stateful case). Unmatched requests get a synthetic 404."""

    def __init__(self, cassette: Cassette) -> None:
        self.cassette = cassette
        self._by_key: dict[tuple, list] = {}
        for inter in cassette.interactions:
            req = inter.get("request", {})
            key = (str(req.get("method", "GET")).upper(), req.get("path", "/"))
            self._by_key.setdefault(key, []).append(inter.get("response", {}))
        self._cursor: dict[tuple, int] = {}

    def request(self, method: str, path: str) -> RecordedResponse:
        key = (method.upper(), path)
        seq = self._by_key.get(key)
        if not seq:
            return RecordedResponse(status=404, body="")
        i = self._cursor.get(key, 0)
        resp = seq[min(i, len(seq) - 1)]      # last response sticks once exhausted
        self._cursor[key] = i + 1
        headers = resp.get("headers", {})
        return RecordedResponse(
            status=int(resp.get("status", 200)),
            headers=headers,
            body=resp.get("body", ""),
            cookies=_parse_cookies(headers),
        )


class CassetteHttpClient:
    """A minimal HTTP client backed by a CassettePlayer — what sensors call instead
    of touching the network."""

    def __init__(self, cassette: Cassette) -> None:
        self.cassette = cassette
        self.player = CassettePlayer(cassette)

    def fetch(self, method: str, path: str) -> RecordedResponse:
        return self.player.request(method, path)

    def http_response(self, path: str = "/") -> HttpResponse:
        r = self.fetch("GET", path)
        return HttpResponse.from_html(
            host=self.cassette.host, html=r.body, headers=r.headers,
            port=self.cassette.port, status=r.status, cookies=r.cookies, url=path,
        )


# ── Stateful probe executor (a minimal Nuclei-style multi-request check) ─────────

def _subst(s: str, ctx: dict) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: str(ctx.get(m.group(1), m.group(0))), s or "")


def run_probe(client: CassetteHttpClient, probe: dict) -> tuple[bool, str]:
    """Execute a probe's ordered steps against the cassette, carrying extracted state
    (tokens/cookies) forward. Returns (confirmed, evidence). Confirmed only if the
    final step's `success` regex matches — proving the stateful sequence worked."""
    ctx: dict = {}
    evidence = ""
    steps = probe.get("steps", [])
    for idx, step in enumerate(steps):
        method = str(step.get("method", "GET"))
        path = _subst(step.get("path", "/"), ctx)
        resp = client.fetch(method, path)
        # carry forward extracted variables (e.g. CSRF token) for later steps
        for var, pat in (step.get("extract") or {}).items():
            m = re.search(pat, resp.body or "")
            if m:
                ctx[var] = m.group(1) if m.groups() else m.group(0)
        success = step.get("success")
        if success:
            m = re.search(success, resp.body or "")
            if not m:
                return (False, f"step {idx + 1} success marker not found")
            evidence = (m.group(0) or "")[:160]
    return (bool(evidence), evidence)


# ── Cassette -> Signals (run real sensors against recorded traffic) ──────────────

def signals_from_cassette(cassette: Cassette) -> list[Signal]:
    client = CassetteHttpClient(cassette)
    signals: list[Signal] = []

    # 1. Fingerprinting sensor over the primary recorded response.
    primary = client.http_response("/")
    for s in Wappalyzer().detect(primary):
        s.exposure = cassette.exposure
        signals.append(s)

    # 2. Stateful probes — emit a probe-confirmed vuln Signal on success.
    for probe in cassette.probes:
        confirmed, evidence = run_probe(CassetteHttpClient(cassette), probe)
        if confirmed:
            signals.append(Signal(
                source="probe", kind="vuln", claim=probe["claim"],
                host=cassette.host, port=cassette.port, service="http",
                reliability="high",                      # probe-confirmed → pinned by the gate
                evidence=evidence,
                cvss=float(probe.get("cvss", 0.0)),
                kev=bool(probe.get("kev", False)),
                exploit_available=bool(probe.get("exploit_available", False)),
                exposure=cassette.exposure,
            ))

    # 3. Version-matched CVE candidates — unconfirmed leads (the realistic gray band the
    #    AI must adjudicate). One signal per source so corroboration is modeled honestly.
    for cand in cassette.cve_candidates:
        for src in (cand.get("sources") or ["nvd"]):
            signals.append(Signal(
                source=src, kind="vuln", claim=cand["claim"],
                host=cassette.host, port=cassette.port, service="http",
                reliability=cand.get("reliability", "medium"),
                evidence=cand.get("evidence", ""),
                cvss=float(cand.get("cvss", 0.0)),
                kev=bool(cand.get("kev", False)),
                exploit_available=bool(cand.get("exploit_available", False)),
                exposure=cassette.exposure,
            ))
    return signals


def cassette_truth(cassette: Cassette) -> dict:
    truth = {}
    for t in cassette.truth:
        key = (cassette.host, int(t.get("port", cassette.port)), str(t["claim"]).lower().strip())
        truth[key] = {"is_real": bool(t.get("is_real")), "severity": t.get("severity", "low")}
    return truth
