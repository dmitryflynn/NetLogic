"""
Fusion sensor — Nuclei YAML template parser (simple-HTTP-matcher subset).

Parses ProjectDiscovery Nuclei templates that use the HTTP protocol with simple
matchers (words, regex, status) and emits one Signal per matched template.

SEVERITY STRIPPING: The template's ``info.severity`` is NEVER propagated to the
Signal — it is a self-declared label from a third-party template author, not an
observed fact. The deterministic gate computes its own impact band from KEV/CVSS.

Scope:
  • HTTP protocol only (not DNS, TCP, etc.)
  • Simple matchers: word, regex, status
  • matchers-condition: and/or
  • matcher-level condition: and/or
  • Parts: body, header, status_code
  • negative matchers
  • case-insensitive matching
  • hex-encoded word matchers
  • Regex extractors
  • Multiple paths per request block (sequentially tried, first match wins)
  • stop-at-first-match within a request block

Out of scope (interactsh, dsl, xpath, binary, network-level, multi-request
chaining with extractor variables, complex extractors like kval/xpath):
these require remote callbacks or multi-step state.

Data: loads .yaml files from ``src/fusion/data/nuclei/`` or
``$NETLOGIC_NUCLEI_DATA``.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional

from src.fusion.signals import Signal
from src.fusion.sensors.wappalyzer import HttpResponse

log = logging.getLogger("netlogic.fusion.nuclei")

# Hard cap on evidence length shown to the gate/AI (bounds context size).
_MAX_EVIDENCE = 600

_DATA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "nuclei"
)


def _re_search(pattern: str, text: str):
    """re.search that returns None instead of raising on a Go/PCRE-only pattern Python's
    re can't compile. Real Nuclei templates routinely carry such regexes; a single one
    must never crash the scan — skip it and keep going (higher effective recall)."""
    try:
        return re.search(pattern, text)
    except re.error:
        return None


def _re_matches(pattern: str, text: str) -> bool:
    return _re_search(pattern, text) is not None


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _decode_hex_words(words: list[str]) -> list[str]:
    """Decode hex-encoded words (``encoding: hex``) into plain strings."""
    out = []
    for w in words:
        try:
            out.append(bytes.fromhex(w).decode("utf-8", errors="replace"))
        except (ValueError, AttributeError):
            out.append(w)
    return out


def _get_part(resp: HttpResponse, rec: dict, part: str) -> Optional[str]:
    """Extract the matchable part from an HttpResponse.

    ``part`` is one of ``body``, ``header``, ``status_code``.
    """
    if part == "body":
        return resp.html
    if part == "header":
        # Match against the full raw header block.
        lines = []
        for k, v in resp.headers.items():
            lines.append(f"{k}: {v}")
        return "\r\n".join(lines)
    if part in ("status_code",):
        return str(resp.status)
    return None


def _match_word(part_val: str, words: list[str], case_insensitive: bool) -> bool:
    if case_insensitive:
        part_val = part_val.lower()
        return any(w.lower() in part_val for w in words)
    return any(w in part_val for w in words)


def _match_regex(part_val: str, patterns: list[str]) -> bool:
    return any(_re_matches(p, part_val) for p in patterns)


def _match_status(part_val: str, statuses: list[int]) -> bool:
    try:
        return int(part_val) in statuses
    except (ValueError, TypeError):
        return False


def _eval_matcher(matcher: dict, resp: HttpResponse) -> bool:
    """Evaluate a single matcher against the response. Returns True if matched."""
    mtype = matcher.get("type", "word")
    part = matcher.get("part", "body")
    condition = matcher.get("condition", "or")
    negative = bool(matcher.get("negative", False))
    case_insensitive = bool(matcher.get("case-insensitive", False))
    encoding = matcher.get("encoding", "")

    matched = False

    if mtype == "status":
        statuses = matcher.get("status", [])
        matched = _match_status(str(resp.status), statuses)

    elif mtype == "word":
        part_val = _get_part(resp, matcher, part)
        if part_val is None:
            return False
        words = matcher.get("words", [])
        if encoding == "hex":
            words = _decode_hex_words(words)
        if condition == "and":
            matched = all(
                (w.lower() in part_val.lower()) if case_insensitive else (w in part_val)
                for w in words
            ) if words else False
        else:
            matched = _match_word(part_val, words, case_insensitive) if words else False

    elif mtype == "regex":
        part_val = _get_part(resp, matcher, part)
        if part_val is None:
            return False
        patterns = matcher.get("regex", [])
        if condition == "and":
            matched = all(_re_matches(p, part_val) for p in patterns) if patterns else False
        else:
            matched = _match_regex(part_val, patterns) if patterns else False

    if negative:
        matched = not matched

    return matched


def _run_extractors(extractors: list[dict], resp: HttpResponse) -> dict:
    """Run extractors against the response and return extracted values."""
    extracted: dict = {}
    if not extractors:
        return extracted
    for ext in extractors:
        etype = ext.get("type", "")
        if etype != "regex":
            continue
        part = ext.get("part", "body")
        part_val = _get_part(resp, ext, part)
        if part_val is None:
            continue
        patterns = ext.get("regex", [])
        group = int(ext.get("group", 0))
        name = ext.get("name", "")
        for pat in patterns:
            m = _re_search(pat, part_val)
            if m:
                try:
                    val = m.group(group)
                except (IndexError, ValueError):
                    val = m.group(0)
                if name:
                    extracted[name] = val
                else:
                    extracted.setdefault("_extracted", []).append(val)
                break  # first matching pattern wins
    return extracted


# ── Template loading ─────────────────────────────────────────────────────────────


def _coalesce_list(v: Any) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


class NucleiTemplate:
    """A single parsed Nuclei template with its matchers and metadata.

    Severity from ``info.severity`` is stored for audit (``raw_metadata``) but
    NEVER emitted into the Signal's impact fields.
    """

    def __init__(self, data: dict) -> None:
        self.id: str = str(data.get("id", ""))
        info = data.get("info") or {}
        self.name: str = str(info.get("name", self.id))
        self.severity: str = str(info.get("severity", "info"))
        raw_tags = info.get("tags")
        if isinstance(raw_tags, str):
            self.tags: list[str] = [t.strip() for t in raw_tags.split(",") if t.strip()]
        elif isinstance(raw_tags, list):
            self.tags = [str(t).strip() for t in raw_tags]
        else:
            self.tags = []
        classification = info.get("classification") or {}
        self.cvss: float = float(classification.get("cvss-score", 0.0) or 0.0)
        self.cve_id: str = str(classification.get("cve-id", "") or "")
        self.epss: float = float(classification.get("epss-score", 0.0) or 0.0)
        self.kev: bool = "kev" in [t.strip().lower() for t in self.tags]
        self.metadata: dict = info.get("metadata") or {}

        http_blocks = data.get("http", [])
        self.requests: list[dict] = []
        for block in _coalesce_list(http_blocks):
            self.requests.append(block)

    @property
    def has_matchers(self) -> bool:
        return any(
            block.get("matchers") for block in self.requests
        )


def load_templates(path: Optional[str] = None) -> list[NucleiTemplate]:
    """Load all Nuclei YAML templates from a directory.

    PyYAML is imported LAZILY and is OPTIONAL: if it isn't installed, Nuclei templates
    are simply unavailable (returns []). Importing this module — and therefore the rest
    of the fusion pipeline — never depends on PyYAML, so a missing dependency degrades
    one sensor instead of breaking the whole package.
    """
    try:
        import yaml  # noqa: PLC0415 — optional dep, only needed to parse templates
    except ImportError:
        log.warning("PyYAML not installed — Nuclei templates unavailable. `pip install pyyaml`.")
        return []
    directory = path or _DATA_DIR
    templates: list[NucleiTemplate] = []
    if not os.path.isdir(directory):
        return templates
    for fname in sorted(os.listdir(directory)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        fpath = os.path.join(directory, fname)
        try:
            with open(fpath, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except (OSError, yaml.YAMLError) as exc:
            log.warning("failed to load nuclei template %s: %s", fname, exc)
            continue
        if not isinstance(data, dict):
            continue
        if data.get("http") is None:
            continue  # skip non-HTTP templates
        templates.append(NucleiTemplate(data))
    return templates


# ── The sensor ───────────────────────────────────────────────────────────────────


class Nuclei:
    """Nuclei-template sensor — matches recorded responses against templates."""

    def __init__(self, templates: Optional[list[NucleiTemplate]] = None,
                 directory: Optional[str] = None) -> None:
        self.templates = templates if templates is not None else load_templates(directory)

    def detect(self, resp: HttpResponse, path: str = "/") -> list[Signal]:
        """Run all templates against one HttpResponse.

        ``path`` is the URL path that produced this response (for path-specific
        templates like ``/.git/config``).
        """
        signals: list[Signal] = []
        for tmpl in self.templates:
            s = self._match_template(tmpl, resp, path)
            if s is not None:
                signals.append(s)
        return signals

    def _match_template(self, tmpl: NucleiTemplate, resp: HttpResponse, path: str) -> Optional[Signal]:
        """Try each HTTP request block in the template against the response.

        Returns a Signal if any request block matches, else None.
        """
        if not tmpl.requests:
            return None

        for block in tmpl.requests:
            paths = _coalesce_list(block.get("path", []))
            matchers = _coalesce_list(block.get("matchers", []))
            matchers_condition = block.get("matchers-condition", "or")
            extractors = _coalesce_list(block.get("extractors", []))
            stop_at_first = bool(block.get("stop-at-first-match", False))

            if not matchers:
                continue

            for req_path in paths:
                # Normalize {{BaseURL}} — we check if the requested path matches.
                # The sensor only has ONE response, so we match against the path
                # that was actually requested.
                norm = self._normalize_path(req_path)
                if not self._path_matches(norm, path):
                    continue

                matched = self._eval_matchers(matchers, matchers_condition, resp)
                if not matched:
                    if stop_at_first:
                        break
                    continue

                extracted = _run_extractors(extractors, resp)

                evidence_parts: list[str] = []
                for m in matchers:
                    self._describe_matcher(m, evidence_parts)

                claim = tmpl.cve_id if tmpl.cve_id else tmpl.id

                # Severity is deliberately NOT passed to Signal — the gate
                # computes its own impact from KEV/CVSS/EPSS.
                signal = Signal(
                    source="nuclei",
                    kind="vuln" if tmpl.cve_id else "exposure",
                    claim=claim.lower(),
                    host=resp.host,
                    port=resp.port,
                    service="http",
                    evidence="; ".join(evidence_parts)[:_MAX_EVIDENCE],
                    confidence=0.7,
                    reliability="medium",
                    cvss=tmpl.cvss,
                    kev=tmpl.kev,
                    epss=tmpl.epss,
                    raw_metadata={
                        "template_id": tmpl.id,
                        "template_name": tmpl.name,
                        "template_severity": tmpl.severity,
                        "tags": tmpl.tags,
                        "extracted": extracted,
                    },
                )
                return signal
        return None

    def _normalize_path(self, raw: str) -> str:
        """Normalize a template path like ``{{BaseURL}}/.git/config`` or
        ``{{BaseURL}}`` into a relatable form."""
        p = raw.replace("{{BaseURL}}", "")
        p = p.replace("{{Path}}", "")
        return p or "/"

    def _path_matches(self, norm: str, actual: str) -> bool:
        """Check if the normalized template path matches the actual request path."""
        # Simple prefix/suffix match within the same request block.
        # If the template path is "/" it matches everything.
        if norm == "/":
            return True
        # Template path "/admin" should match actual "/admin" but not "/admin2"
        if actual == norm:
            return True
        # Template path "/admin" should also match actual "/admin/"
        if actual.rstrip("/") == norm.rstrip("/"):
            return True
        return False

    def _eval_matchers(self, matchers: list[dict], condition: str, resp: HttpResponse) -> bool:
        if not matchers:
            return False
        if condition == "and":
            return all(_eval_matcher(m, resp) for m in matchers)
        return any(_eval_matcher(m, resp) for m in matchers)

    def _describe_matcher(self, matcher: dict, out: list[str]) -> None:
        mtype = matcher.get("type", "word")
        part = matcher.get("part", "body")
        neg = "NOT " if matcher.get("negative") else ""
        if mtype == "word":
            words = matcher.get("words", [])
            snippet = ", ".join(str(w)[:60] for w in words[:3])
            if len(words) > 3:
                snippet += "..."
            out.append(f"{neg}word[{part}]:{snippet}")
        elif mtype == "regex":
            pats = matcher.get("regex", [])
            snippet = ", ".join(str(p)[:40] for p in pats[:2])
            if len(pats) > 2:
                snippet += "..."
            out.append(f"{neg}regex[{part}]:{snippet}")
        elif mtype == "status":
            codes = matcher.get("status", [])
            out.append(f"status:{codes}")
