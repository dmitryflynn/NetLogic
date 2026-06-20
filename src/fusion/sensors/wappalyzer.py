"""
Fusion sensor — Wappalyzer-style technology fingerprinting (zero-dependency).

Parses the open Wappalyzer fingerprint format (headers / cookies / html / scriptSrc
/ meta / url patterns, with `\\;version:\\1` and `\\;confidence:NN` tags and
`implies`) and runs it against an HTTP response, emitting one `Signal` per detected
technology. It is deliberately a SENSOR: it asserts "I observed X, here's the
evidence," never "X is a vulnerability." A lone tech detection is inventory — the
gate auto-discards it unless something corroborates it.

Precision notes:
  • Only emits a signal when a pattern actually matches; carries the matched
    evidence so the gate/AI can see WHY.
  • Bad/incompatible regexes are skipped (never crash, never match-by-accident).
  • Detected version goes into raw_metadata (used later for CVE correlation),
    never inflated into severity here.

Data: ships a minimal hand-authored fingerprint set; prefers a full open dataset
(webappanalyzer/enthec) at src/fusion/data/wappalyzer.json or $NETLOGIC_WAPPALYZER_DATA.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from src.fusion.signals import Signal

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


# ── HTTP response the sensor consumes ───────────────────────────────────────────

@dataclass
class HttpResponse:
    host: str
    port: int = 80
    url: str = ""
    status: int = 0
    headers: dict = field(default_factory=dict)   # name -> value (case-insensitive lookup)
    html: str = ""
    cookies: dict = field(default_factory=dict)    # name -> value
    scripts: list = field(default_factory=list)    # <script src> values
    metas: dict = field(default_factory=dict)       # meta name (lower) -> content

    def header(self, name: str) -> Optional[str]:
        nl = name.lower()
        for k, v in self.headers.items():
            if k.lower() == nl:
                return v
        return None

    @classmethod
    def from_html(cls, host: str, html: str = "", headers: Optional[dict] = None, **kw) -> "HttpResponse":
        """Convenience: derive scriptSrc + meta tags from raw HTML."""
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)
        metas: dict = {}
        for m in re.finditer(
            r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)', html, re.I
        ):
            metas[m.group(1).lower()] = m.group(2)
        return cls(host=host, html=html, headers=headers or {}, scripts=scripts, metas=metas, **kw)


# ── Pattern parsing (Wappalyzer format) ─────────────────────────────────────────

def _parse_pattern(p: str) -> tuple[str, Optional[str], int]:
    """Split 'regex\\;version:\\1\\;confidence:NN' into (regex, version_tmpl, confidence)."""
    parts = p.split("\\;")
    regex = parts[0]
    version, confidence = None, 100
    for extra in parts[1:]:
        if extra.startswith("version:"):
            version = extra[len("version:"):]
        elif extra.startswith("confidence:"):
            try:
                confidence = int(extra[len("confidence:"):])
            except ValueError:
                pass
    return regex, version, confidence


def _apply_version(template: Optional[str], m: "re.Match") -> Optional[str]:
    if not template:
        return None
    # Common ternary form: \1?\1:  → "use group 1 if present".
    tern = re.match(r"\\(\d)\?\\\d:?.*$", template)
    if tern:
        try:
            return (m.group(int(tern.group(1))) or None)
        except (IndexError, re.error):
            return None

    def repl(mm: "re.Match") -> str:
        try:
            return m.group(int(mm.group(1))) or ""
        except (IndexError, re.error):
            return ""

    out = re.sub(r"\\(\d)", repl, template).strip()
    return out or None


def _test(pattern: str, value: Optional[str]) -> tuple[bool, Optional[str], int]:
    """Return (matched, version, confidence) for one pattern against one value."""
    if value is None:
        return (False, None, 0)
    regex, vtmpl, conf = _parse_pattern(pattern)
    if regex == "":
        return (True, None, conf)          # empty pattern = presence check
    try:
        m = re.search(regex, value, re.I)
    except re.error:
        return (False, None, 0)            # incompatible regex → skip, never match by accident
    if not m:
        return (False, None, 0)
    return (True, _apply_version(vtmpl, m), conf)


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# ── Dataset loading ─────────────────────────────────────────────────────────────

def load_fingerprints(path: Optional[str] = None) -> dict:
    """Load the technologies dict, preferring a full open dataset over the minimal seed."""
    candidates = [
        path,
        os.environ.get("NETLOGIC_WAPPALYZER_DATA"),
        os.path.join(_DATA_DIR, "wappalyzer.json"),
        os.path.join(_DATA_DIR, "wappalyzer_min.json"),
    ]
    for c in candidates:
        if c and os.path.exists(c):
            try:
                with open(c, encoding="utf-8") as fh:
                    data = json.load(fh)
                return data.get("technologies", data) if isinstance(data, dict) else {}
            except (OSError, json.JSONDecodeError):
                continue
    return {}


# ── The sensor ──────────────────────────────────────────────────────────────────

class Wappalyzer:
    def __init__(self, data: Optional[dict] = None) -> None:
        self.data = data if data is not None else load_fingerprints()

    def detect(self, resp: HttpResponse) -> list[Signal]:
        matched: dict[str, dict] = {}
        for tech, spec in self.data.items():
            if tech.startswith("_"):
                continue
            ev, conf, version = self._match_tech(spec, resp)
            if ev:
                matched[tech] = {"confidence": conf, "version": version, "evidence": ev, "implied": False}

        # `implies`: directly-detected techs imply others (inferred → low reliability).
        for tech in list(matched):
            for imp in _as_list(self.data.get(tech, {}).get("implies")):
                name, _v, c = _parse_pattern(imp)
                if name and name not in matched:
                    matched[name] = {"confidence": min(c, 50), "version": None,
                                     "evidence": [f"implied by {tech}"], "implied": True}

        signals: list[Signal] = []
        for tech, info in matched.items():
            signals.append(Signal(
                source="wappalyzer",
                kind="tech",
                claim=tech.lower(),
                host=resp.host,
                port=resp.port,
                service="http",
                evidence="; ".join(info["evidence"]),
                confidence=info["confidence"] / 100.0,
                reliability="low" if info["implied"] else "medium",
                raw_metadata={
                    "version": info["version"],
                    "categories": self.data.get(tech, {}).get("cats", []),
                    "implied": info["implied"],
                },
            ))
        return signals

    def _match_tech(self, spec: dict, resp: HttpResponse) -> tuple[list[str], int, Optional[str]]:
        ev: list[str] = []
        conf = 0
        version: Optional[str] = None

        def consider(ok, v, c, label):
            nonlocal conf, version
            if ok:
                conf = max(conf, c)
                version = version or v
                ev.append(label)

        for hn, pat in (spec.get("headers") or {}).items():
            val = resp.header(hn)
            ok, v, c = _test(pat, val)
            consider(ok, v, c, f"header {hn}: {(val or '')[:80]}")

        for cn, pat in (spec.get("cookies") or {}).items():
            if cn in resp.cookies:
                ok, v, c = _test(pat, resp.cookies[cn] or "")
                consider(ok, v, c, f"cookie {cn}")

        for pat in _as_list(spec.get("html")):
            ok, v, c = _test(pat, resp.html)
            consider(ok, v, c, "html match")

        for pat in _as_list(spec.get("scriptSrc")):
            for src in resp.scripts:
                ok, v, c = _test(pat, src)
                if ok:
                    consider(ok, v, c, f"script {src[:60]}")
                    break

        for mn, pat in (spec.get("meta") or {}).items():
            val = resp.metas.get(mn.lower())
            if val is not None:
                ok, v, c = _test(pat, val)
                consider(ok, v, c, f"meta {mn}: {val[:60]}")

        for pat in _as_list(spec.get("url")):
            ok, v, c = _test(pat, resp.url)
            consider(ok, v, c, "url match")

        return ev, conf, version
