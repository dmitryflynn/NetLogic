"""
Pack benchmark harness (Phase 6.5) — every fingerprint gets a reproducible regression test.

A pack's knowledge is only as good as its test coverage. Each pack declares `benchmark_fixtures`
pointing at recorded responses under `benchmark/<fixture>/`; this harness evaluates the pack's
fingerprints against those recorded responses (offline, deterministic) and reports what matched.
That prevents the knowledge base from silently degrading as it grows to thousands of fingerprints.

A fixture directory contains:
  response.json   {"headers": {...}, "cookies": [...], "body": "...", "favicon_hash": "..."}
  expected.json   {"detect": ["wordpress", ...], "min_markers": 1, "must_not_detect": [...]}
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from src.reasoning.packs.normalize import Normalizer
from src.reasoning.packs.schema import CompiledPack

_NORMALIZER = Normalizer()


@dataclass
class DetectionResult:
    """What a pack matched against one recorded response."""
    pack_id: str
    matched_markers: list[str] = field(default_factory=list)
    matched_kinds: list[str] = field(default_factory=list)   # headers/cookies/body/favicon

    @property
    def detected(self) -> bool:
        return bool(self.matched_markers)


def _response_blob(response: dict, normalizer: Normalizer = _NORMALIZER) -> tuple[str, str, str, str]:
    """(headers, cookies, body, favicon) blobs, CANONICALIZED so fingerprints need not enumerate
    formatting/version variants. See packs/normalize.py."""
    headers_blob = normalizer.header_blob(response.get("headers") or {})
    cookies_blob = normalizer.cookie_blob(response.get("cookies") or [])
    body_blob = normalizer.text_blob(response.get("body", ""))
    favicon = str(response.get("favicon_hash", ""))
    return headers_blob, cookies_blob, body_blob, favicon


def evaluate_pack(pack: CompiledPack, response: dict) -> DetectionResult:
    """Match a pack's fingerprints against a recorded response. Pure, offline, deterministic.
    Observations are normalized before matching (formatting + version variants collapse)."""
    headers_blob, cookies_blob, body_blob, favicon = _response_blob(response)
    res = DetectionResult(pack_id=pack.id)
    fp = pack.fingerprints
    for marker in fp.headers:
        if marker in headers_blob:
            res.matched_markers.append(marker)
            res.matched_kinds.append("headers")
    for marker in fp.cookies:
        if marker in cookies_blob:
            res.matched_markers.append(marker)
            res.matched_kinds.append("cookies")
    for marker in fp.body:
        if marker in body_blob:
            res.matched_markers.append(marker)
            res.matched_kinds.append("body")
    for h in fp.favicon:
        if favicon and h == favicon:
            res.matched_markers.append(h)
            res.matched_kinds.append("favicon")
    return res


def load_fixture(fixture: str, root: str | Path = "benchmark") -> tuple[dict, dict]:
    """Load (response, expected) for a fixture id like 'wordpress/basic'."""
    base = Path(root) / fixture
    response = json.loads((base / "response.json").read_text(encoding="utf-8"))
    expected = json.loads((base / "expected.json").read_text(encoding="utf-8"))
    return response, expected


def run_fixture(library, fixture: str, root: str | Path = "benchmark") -> dict:
    """Evaluate ALL packs in the library against one fixture and check it against expectations.

    Returns {"fixture", "detected": [pack_ids], "passed": bool, "failures": [...]}.
    """
    response, expected = load_fixture(fixture, root)
    detected = []
    for pack in library.all():
        if evaluate_pack(pack, response).detected:
            detected.append(pack.id)

    failures = []
    for want in expected.get("detect", []):
        # resolve aliases so expectations can use any name the pack answers to
        pack = library.get(want)
        wanted_id = pack.id if pack else want
        if wanted_id not in detected:
            failures.append(f"expected to detect {want!r} ({wanted_id})")
    for forbid in expected.get("must_not_detect", []):
        pack = library.get(forbid)
        forbid_id = pack.id if pack else forbid
        if forbid_id in detected:
            failures.append(f"false positive: detected {forbid!r}")

    return {"fixture": fixture, "detected": sorted(detected),
            "passed": not failures, "failures": failures}
