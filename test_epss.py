"""
Focused tests for src/epss.py — EPSS enrichment.

Deterministic and offline: the network fetch (`_fetch_batch`) is always
monkeypatched, and the on-disk cache path is redirected into a tmp dir. We never
touch api.first.org or the developer's real ~/.netlogic.

Guards:
  • cache hit (no fetch) vs miss (fetch)
  • partial batch failure does NOT poison never-queried CVEs
  • stale (>24h) cache is ignored
  • fail-soft on a hard network error (scores stay absent, never raises)
  • enrich_with_epss attaches scores in place
  • cache write is atomic (no corrupt file left on a crash)
"""
import json
import time

import pytest

import src.epss as epss


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Redirect the module-level cache path into a fresh tmp file and reset the
    session 'unavailable' flag before every test."""
    cache_file = tmp_path / "epss_cache.json"
    monkeypatch.setattr(epss, "_CACHE_PATH", cache_file)
    monkeypatch.setattr(epss, "_unavailable", False)
    return cache_file


def _row(cve, score, pct):
    return {cve: {"epss": score, "percentile": pct}}


# --------------------------------------------------------------------------- #
# cache miss / fetch                                                          #
# --------------------------------------------------------------------------- #
def test_fetch_on_miss_and_cache_written(isolated_cache, monkeypatch):
    calls = []

    def fake_fetch(batch):
        calls.append(list(batch))
        return _row("CVE-2021-44228", 0.97, 0.99)

    monkeypatch.setattr(epss, "_fetch_batch", fake_fetch)

    res = epss.get_epss_scores(["CVE-2021-44228"])
    assert res["CVE-2021-44228"]["epss"] == 0.97
    assert len(calls) == 1
    # cache file persisted
    on_disk = json.loads(isolated_cache.read_text())
    assert on_disk["scores"]["CVE-2021-44228"]["epss"] == 0.97


def test_cache_hit_skips_fetch(isolated_cache, monkeypatch):
    isolated_cache.write_text(json.dumps({
        "_fetched": time.time(),
        "scores": {"CVE-2020-0001": {"epss": 0.5, "percentile": 0.8}},
    }))

    def boom(batch):
        raise AssertionError("fetch should not be called on a cache hit")

    monkeypatch.setattr(epss, "_fetch_batch", boom)

    res = epss.get_epss_scores(["CVE-2020-0001"])
    assert res["CVE-2020-0001"]["epss"] == 0.5


# --------------------------------------------------------------------------- #
# the headline bug: partial failure must not poison unqueried CVEs           #
# --------------------------------------------------------------------------- #
def test_partial_failure_does_not_poison_unqueried(isolated_cache, monkeypatch):
    monkeypatch.setattr(epss, "_BATCH", 2)  # force multiple batches

    import urllib.error

    def flaky_fetch(batch):
        # First batch (the two lowest-sorted IDs) succeeds; any later batch dies.
        if "CVE-2000-0001" in batch:
            return _row("CVE-2000-0001", 0.10, 0.20)
        raise urllib.error.URLError("network down mid-loop")

    monkeypatch.setattr(epss, "_fetch_batch", flaky_fetch)

    ids = ["CVE-2000-0001", "CVE-2000-0002", "CVE-2000-0003", "CVE-2000-0004"]
    res = epss.get_epss_scores(ids)

    # Batch 1 result present.
    assert res.get("CVE-2000-0001", {}).get("epss") == 0.10

    # The never-queried CVEs from the failed batch must NOT be in the result...
    assert "CVE-2000-0003" not in res
    assert "CVE-2000-0004" not in res

    # ...and must NOT be persisted as 0.0 in the cache (the poisoning bug).
    on_disk = json.loads(isolated_cache.read_text())["scores"]
    assert "CVE-2000-0003" not in on_disk
    assert "CVE-2000-0004" not in on_disk

    # A later run (network back) must actually re-query them, not serve 0.0.
    seen = []

    def good_fetch(batch):
        seen.extend(batch)
        return {c: {"epss": 0.42, "percentile": 0.5} for c in batch}

    monkeypatch.setattr(epss, "_unavailable", False)
    monkeypatch.setattr(epss, "_fetch_batch", good_fetch)
    res2 = epss.get_epss_scores(["CVE-2000-0003", "CVE-2000-0004"])
    assert "CVE-2000-0003" in seen and "CVE-2000-0004" in seen
    assert res2["CVE-2000-0003"]["epss"] == 0.42


def test_missing_from_completed_batch_recorded_zero(isolated_cache, monkeypatch):
    """A CVE the API simply doesn't return (but we DID query) is cached as 0.0
    so we don't re-query it every scan."""
    def fetch(batch):
        return _row("CVE-2021-1", 0.3, 0.4)  # only returns one of two queried

    monkeypatch.setattr(epss, "_fetch_batch", fetch)
    res = epss.get_epss_scores(["CVE-2021-1", "CVE-2021-2"])
    assert res["CVE-2021-1"]["epss"] == 0.3
    assert res["CVE-2021-2"]["epss"] == 0.0  # queried, not returned -> 0.0
    on_disk = json.loads(isolated_cache.read_text())["scores"]
    assert on_disk["CVE-2021-2"] == {"epss": 0.0, "percentile": 0.0}


# --------------------------------------------------------------------------- #
# stale cache                                                                #
# --------------------------------------------------------------------------- #
def test_stale_cache_ignored(isolated_cache, monkeypatch):
    isolated_cache.write_text(json.dumps({
        "_fetched": time.time() - (epss._CACHE_TTL + 100),
        "scores": {"CVE-2019-0001": {"epss": 0.99, "percentile": 0.99}},
    }))

    def fresh_fetch(batch):
        return _row("CVE-2019-0001", 0.01, 0.02)

    monkeypatch.setattr(epss, "_fetch_batch", fresh_fetch)
    res = epss.get_epss_scores(["CVE-2019-0001"])
    # Stale value (0.99) ignored; re-fetched fresh value (0.01) used.
    assert res["CVE-2019-0001"]["epss"] == 0.01


# --------------------------------------------------------------------------- #
# fail-soft                                                                  #
# --------------------------------------------------------------------------- #
def test_fail_soft_on_network_error(isolated_cache, monkeypatch):
    import urllib.error

    def dead(batch):
        raise urllib.error.URLError("no network")

    monkeypatch.setattr(epss, "_fetch_batch", dead)
    # Must not raise, and returns nothing for the unresolved CVE.
    res = epss.get_epss_scores(["CVE-2022-0001"])
    assert res == {}
    # Nothing poisoned on disk.
    assert not isolated_cache.exists()


def test_non_cve_ids_filtered(isolated_cache, monkeypatch):
    monkeypatch.setattr(epss, "_fetch_batch",
                        lambda b: (_ for _ in ()).throw(AssertionError("no fetch")))
    assert epss.get_epss_scores(["", None, "GHSA-xxxx", "not-a-cve"]) == {}


# --------------------------------------------------------------------------- #
# enrich_with_epss attaches in place                                         #
# --------------------------------------------------------------------------- #
class _CVE:
    def __init__(self, cid):
        self.id = cid
        self.epss = 0.0
        self.epss_percentile = 0.0


class _VM:
    def __init__(self, cves):
        self.cves = cves


def test_enrich_attaches_in_place(isolated_cache, monkeypatch):
    def fetch(batch):
        return {c: {"epss": 0.55, "percentile": 0.66} for c in batch}

    monkeypatch.setattr(epss, "_fetch_batch", fetch)

    cve = _CVE("CVE-2023-1234")
    vm = _VM([cve])
    epss.enrich_with_epss([vm])
    assert cve.epss == 0.55
    assert cve.epss_percentile == 0.66


def test_enrich_handles_empty_and_none(isolated_cache, monkeypatch):
    monkeypatch.setattr(epss, "_fetch_batch",
                        lambda b: (_ for _ in ()).throw(AssertionError("no fetch")))
    # Should not raise on empty / None input.
    epss.enrich_with_epss([])
    epss.enrich_with_epss(None)
    epss.enrich_with_epss([_VM([])])


# --------------------------------------------------------------------------- #
# atomic write — no corrupt/leftover temp file                               #
# --------------------------------------------------------------------------- #
def test_save_cache_atomic_no_tmp_left(isolated_cache, tmp_path):
    epss._save_cache({"CVE-2021-44228": {"epss": 0.9, "percentile": 0.9}})
    assert isolated_cache.exists()
    # valid JSON, and no stray *.tmp sibling left behind
    json.loads(isolated_cache.read_text())
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == []
