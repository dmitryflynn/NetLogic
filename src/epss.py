"""
NetLogic - EPSS Enrichment
==========================
EPSS (Exploit Prediction Scoring System, https://www.first.org/epss) gives each
CVE a 0–1 probability that it will be exploited in the wild in the next 30 days.

This is the single best PRIORITIZATION signal for an unauthenticated scanner: a
host can match dozens of CVSS-9.8 CVEs, but EPSS tells you which handful are
actually likely to be attacked. We attach the score to every correlated CVE and
let the reporter/AI sort and triage by it.

Stdlib-only (urllib). Results are cached to ~/.netlogic/epss_cache.json for 24h.
Fails soft — no network / API error just leaves scores at 0.0.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_EPSS_API = "https://api.first.org/data/v1/epss"
_CACHE_PATH = Path(os.environ.get("NETLOGIC_DATA_DIR",
                                  os.path.join(os.path.expanduser("~"), ".netlogic"))) / "epss_cache.json"
_CACHE_TTL = 86400          # 24h — EPSS is republished daily
_BATCH = 100               # CVEs per API request
_unavailable = False        # set True after a hard network failure this session


def _load_cache() -> dict:
    try:
        raw = json.loads(_CACHE_PATH.read_text())
        if time.time() - raw.get("_fetched", 0) <= _CACHE_TTL:
            return raw.get("scores", {})
    except Exception:
        pass
    return {}


def _save_cache(scores: dict) -> None:
    tmp = None
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: serialise to a sibling temp file then rename over the
        # target, so a crash mid-write can never leave a half-written (corrupt)
        # cache that would force every CVE to be re-fetched forever.
        payload = json.dumps({"_fetched": time.time(), "scores": scores})
        tmp = _CACHE_PATH.with_name(_CACHE_PATH.name + f".{os.getpid()}.tmp")
        tmp.write_text(payload)
        os.replace(tmp, _CACHE_PATH)
    except OSError:
        if tmp is not None:
            try:
                tmp.unlink()
            except OSError:
                pass


def _fetch_batch(cve_ids: list[str]) -> dict:
    """Query the EPSS API for a batch of CVE IDs → {cve: {epss, percentile}}."""
    url = _EPSS_API + "?" + urllib.parse.urlencode({"cve": ",".join(cve_ids)})
    req = urllib.request.Request(url, headers={"User-Agent": "NetLogic/2.0"})
    out = {}
    with urllib.request.urlopen(req, timeout=20) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    for row in body.get("data", []):
        cid = row.get("cve")
        if not cid:
            continue
        try:
            out[cid] = {"epss": float(row.get("epss", 0) or 0),
                        "percentile": float(row.get("percentile", 0) or 0)}
        except (TypeError, ValueError):
            continue
    return out


def get_epss_scores(cve_ids) -> dict:
    """Return {cve_id: {"epss": float, "percentile": float}} for the given CVEs.

    Uses the on-disk cache first, fetches only the misses, and never raises.
    """
    global _unavailable
    ids = sorted({c for c in cve_ids if c and c.upper().startswith("CVE-")})
    if not ids:
        return {}

    cache = _load_cache()
    result = {c: cache[c] for c in ids if c in cache}
    missing = [c for c in ids if c not in cache]

    if missing and not _unavailable:
        fetched = {}
        queried = []          # only CVEs in batches that actually completed
        for i in range(0, len(missing), _BATCH):
            batch = missing[i:i + _BATCH]
            try:
                fetched.update(_fetch_batch(batch))
            except (urllib.error.URLError, urllib.error.HTTPError, OSError):
                # Hard network failure: stop and do NOT touch CVEs we never
                # queried. Backfilling them with 0.0 here would poison the cache
                # for 24h, hiding real exploit probabilities (precision bug).
                _unavailable = True
                break
            except Exception:
                # Malformed response for this batch — skip it, but keep going.
                # Don't mark it queried, so its CVEs stay unknown (not 0.0).
                continue
            queried.extend(batch)
        if queried:
            cache.update(fetched)
            # CVEs in a completed batch that the API didn't return have no
            # published EPSS — record 0 so we don't re-query them every scan.
            # Only CVEs we actually queried get this treatment.
            for c in queried:
                cache.setdefault(c, {"epss": 0.0, "percentile": 0.0})
            _save_cache(cache)
            result.update({c: cache[c] for c in queried if c in cache})

    return result


def enrich_with_epss(vuln_matches) -> None:
    """Attach .epss / .epss_percentile to every CVE in the VulnMatch list (in place)."""
    cve_ids = [getattr(c, "id", None)
               for vm in (vuln_matches or [])
               for c in getattr(vm, "cves", []) or []]
    scores = get_epss_scores(cve_ids)
    if not scores:
        return
    for vm in vuln_matches:
        for c in getattr(vm, "cves", []) or []:
            s = scores.get(getattr(c, "id", ""))
            if s:
                try:
                    c.epss = s["epss"]
                    c.epss_percentile = s["percentile"]
                except Exception:
                    pass
