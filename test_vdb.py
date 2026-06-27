"""
Focused tests for the offline VDB (src/vdb_engine.py, src/vdb_syncer.py).

Deterministic and fully offline: no real NVD network calls and no use of the
developer's real ~/.netlogic. Each test points the engine at a fresh temp
SQLite file and resets the per-thread connection so tests don't leak state.

Guards the production-readiness fixes:
  • local_match precision (versioned CONFIRMED vs patched suppression)
  • the "[]"-string suppression bug (legit POTENTIAL no longer swallowed)
  • init / corruption fail-soft (never raises, degrades to empty)
  • freshness never marks a stale DB "fresh" on backward clock skew
  • syncer never updates the freshness clock when nothing was fetched
"""
import json
import os

import pytest

from src import vdb_engine as ve
from src.nvd_lookup import NVDCve


@pytest.fixture
def engine(tmp_path, monkeypatch):
    """A VdbEngine bound to an isolated temp DB."""
    vdb_dir = tmp_path / "vdb"
    monkeypatch.setattr(ve, "VDB_DIR", str(vdb_dir))
    monkeypatch.setattr(ve, "VDB_PATH", str(vdb_dir / "vuln_db.sqlite"))
    eng = ve.VdbEngine()
    yield eng
    eng._reset_connection()


def _cve(cid, cvss=9.0, vs=None, ve_=None, vei=False, ranges=None, desc="openssh server vulnerability"):
    c = NVDCve(
        id=cid, description=desc, cvss_score=cvss, severity="HIGH",
        vector="", published="", last_modified="", cwe="",
    )
    c.version_start = vs
    c.version_end = ve_
    c.version_end_including = vei
    c.version_ranges = ranges or []
    c.references = ["https://example.test/advisory"]
    c.kev = False
    c.has_metasploit = False
    return c


# ─── init ────────────────────────────────────────────────────────────────────

def test_is_initialized_false_when_no_file(engine):
    assert engine.is_initialized() is False


def test_is_initialized_false_when_empty(engine):
    # Connecting creates the schema but inserts no rows.
    engine.connect()
    assert engine.is_initialized() is False


def test_is_initialized_true_after_import(engine):
    engine.import_nvd_data("openssh", [_cve("CVE-2024-0001", vs="7.0", ve_="8.0")])
    assert engine.is_initialized() is True


# ─── local_match precision ───────────────────────────────────────────────────

def test_confirmed_match_in_range(engine):
    engine.import_nvd_data("openssh", [_cve("CVE-2024-1111", ve_="8.0", vei=False)])
    res = engine.local_match("openssh", "7.9")
    ids = {r.id: r.match_status for r in res}
    assert ids.get("CVE-2024-1111") == "CONFIRMED"


def test_patched_version_not_matched(engine):
    # < 8.0 vuln; 9.0 is patched -> must NOT be reported (false-positive guard).
    engine.import_nvd_data("openssh", [_cve("CVE-2024-1111", ve_="8.0", vei=False)])
    res = engine.local_match("openssh", "9.0")
    assert res == []


def test_versionless_potential_surfaces_when_no_range_data(engine):
    # A high-CVSS row with NO range data at all -> POTENTIAL is allowed through.
    engine.import_nvd_data("openssh", [_cve("CVE-NOVER", cvss=8.5)])
    res = engine.local_match("openssh", "9.9")
    statuses = {r.id: r.match_status for r in res}
    assert statuses.get("CVE-NOVER") == "POTENTIAL"


def test_low_cvss_versionless_is_dropped(engine):
    engine.import_nvd_data("openssh", [_cve("CVE-LOWNOVER", cvss=4.0)])
    assert engine.local_match("openssh", "9.9") == []


def test_potential_not_swallowed_by_empty_json_array(engine):
    """Regression: import_nvd_data stores '[]' for a no-range CVE. The empty
    JSON-array string is truthy, and the old suppression guard treated it as
    'range data present' and dropped the legitimate POTENTIAL row. The match
    must still surface the POTENTIAL."""
    engine.import_nvd_data("openssh", [_cve("CVE-EMPTYJSON", cvss=8.0)])
    # Confirm the stored payload is literally the '[]' string we worry about.
    conn = engine.connect()
    raw = conn.execute(
        "SELECT version_ranges_json FROM vulnerabilities WHERE id='CVE-EMPTYJSON'"
    ).fetchone()[0]
    assert raw == "[]"
    res = engine.local_match("openssh", "9.9")
    assert any(r.id == "CVE-EMPTYJSON" and r.match_status == "POTENTIAL" for r in res)


def test_range_present_but_unmatched_suppresses_potentials(engine):
    """When a relevant row HAS range data but the version is out of range,
    versionless POTENTIALs are intentionally suppressed (trust the filter)."""
    engine.import_nvd_data("openssh", [
        _cve("CVE-RANGE", ve_="8.0"),       # patched at 9.0
        _cve("CVE-NOVER", cvss=8.5),        # versionless POTENTIAL
    ])
    res = engine.local_match("openssh", "9.0")
    assert res == []


def test_result_contract_fields(engine):
    engine.import_nvd_data("openssh", [_cve("CVE-CONTRACT", ve_="8.0")])
    (r,) = [x for x in engine.local_match("openssh", "7.0") if x.id == "CVE-CONTRACT"]
    # Fields consumed by cve_correlator.py
    assert isinstance(r.id, str)
    assert isinstance(r.description, str)
    assert isinstance(r.cvss, float)
    assert r.severity == "HIGH"
    assert r.match_status in ("CONFIRMED", "POTENTIAL")
    assert isinstance(r.kev, bool)
    assert isinstance(r.has_msf, bool)


def test_unknown_product_returns_empty(engine):
    engine.import_nvd_data("openssh", [_cve("CVE-X", ve_="8.0")])
    assert engine.local_match("nonexistent-product", "1.0") == []


def test_blank_inputs_return_empty(engine):
    engine.import_nvd_data("openssh", [_cve("CVE-X", ve_="8.0")])
    assert engine.local_match("", "1.0") == []
    assert engine.local_match("openssh", "") == []


def test_negative_hint_filters_false_positive(engine):
    """A 'dropbear' CVE wrongly imported under the openssh keyword must be
    filtered out by the negative-hint description guard."""
    engine.import_nvd_data("openssh", [
        _cve("CVE-DROPBEAR", ve_="2020.0", desc="Dropbear SSH server flaw"),
    ])
    assert engine.local_match("openssh", "2019.0") == []


# ─── corruption / fail-soft ──────────────────────────────────────────────────

def test_corrupt_db_fails_soft(engine):
    os.makedirs(ve.VDB_DIR, exist_ok=True)
    with open(ve.VDB_PATH, "wb") as fh:
        fh.write(b"this is definitely not a sqlite database")
    # None of these may raise.
    assert engine.is_initialized() is False
    assert engine.local_match("openssh", "8.0") == []
    stats = engine.get_stats()
    assert "error" in stats
    assert engine.get_freshness_status()["status"] == "never_synced"


def test_corrupt_ranges_json_does_not_raise(engine):
    engine.import_nvd_data("openssh", [_cve("CVE-OK", ve_="8.0")])
    conn = engine.connect()
    conn.execute(
        "UPDATE vulnerabilities SET version_ranges_json=? WHERE id='CVE-OK'",
        ("{not valid json",),
    )
    conn.commit()
    # Malformed JSON must be swallowed, falling back to version_start/end.
    res = engine.local_match("openssh", "7.0")
    assert any(r.id == "CVE-OK" for r in res)


# ─── freshness ───────────────────────────────────────────────────────────────

def test_freshness_never_synced(engine):
    engine.import_nvd_data("openssh", [_cve("CVE-X", ve_="8.0")])
    # Imported rows but never called record_sync -> no last_sync metadata.
    assert engine.get_freshness_status()["status"] == "never_synced"


def test_freshness_fresh_after_record(engine):
    engine.import_nvd_data("openssh", [_cve("CVE-X", ve_="8.0")])
    engine.record_sync(1, 1)
    fs = engine.get_freshness_status()
    assert fs["status"] == "fresh"
    assert fs["days_old"] == 0


def test_freshness_clock_skew_not_marked_fresh_negative(engine, monkeypatch):
    """A last_sync timestamp in the future (backward clock move) must not
    produce a negative age. days_old is clamped to >= 0."""
    engine.import_nvd_data("openssh", [_cve("CVE-X", ve_="8.0")])
    engine.record_sync(1, 1)
    # Force the stored timestamp far into the future.
    conn = engine.connect()
    future = int(__import__("time").time()) + 86400 * 365
    conn.execute("UPDATE metadata SET updated_at=? WHERE key='last_sync'", (future,))
    conn.commit()
    fs = engine.get_freshness_status()
    assert fs["days_old"] >= 0


def test_freshness_stale_after_31_days(engine, monkeypatch):
    engine.import_nvd_data("openssh", [_cve("CVE-X", ve_="8.0")])
    engine.record_sync(1, 1)
    conn = engine.connect()
    old = int(__import__("time").time()) - 86400 * 31
    conn.execute("UPDATE metadata SET updated_at=? WHERE key='last_sync'", (old,))
    conn.commit()
    assert engine.get_freshness_status()["status"] == "stale"


# ─── syncer: stale-as-fresh protection ───────────────────────────────────────

def test_syncer_does_not_mark_fresh_when_nothing_fetched(engine, monkeypatch):
    """If NVD returns nothing for every product, run_vdb_sync must NOT call
    record_sync — otherwise an unreachable-NVD failure hides behind a green
    'fresh' timestamp."""
    from src import vdb_syncer

    monkeypatch.setattr(vdb_syncer, "vdb_engine", engine)
    monkeypatch.setattr(vdb_syncer, "SYNC_TARGETS", ["openssh", "nginx"])
    monkeypatch.setattr(vdb_syncer, "query_nvd_for_product", lambda *a, **k: [])

    result = vdb_syncer.run_vdb_sync(limit=0)
    assert result == {"products": 0, "cves": 0}
    # Never synced -> freshness clock untouched.
    assert engine.get_freshness_status()["status"] == "never_synced"


def test_syncer_marks_fresh_when_data_fetched(engine, monkeypatch):
    from src import vdb_syncer

    monkeypatch.setattr(vdb_syncer, "vdb_engine", engine)
    monkeypatch.setattr(vdb_syncer, "SYNC_TARGETS", ["openssh"])
    monkeypatch.setattr(
        vdb_syncer, "query_nvd_for_product",
        lambda *a, **k: [_cve("CVE-2024-9999", ve_="8.0")],
    )

    result = vdb_syncer.run_vdb_sync(limit=0)
    assert result["products"] == 1
    assert result["cves"] == 1
    assert engine.get_freshness_status()["status"] == "fresh"
    # And the imported data is queryable offline.
    assert any(r.id == "CVE-2024-9999" for r in engine.local_match("openssh", "7.0"))


def test_syncer_survives_per_product_exception(engine, monkeypatch):
    """One product blowing up must not abort the whole sync."""
    from src import vdb_syncer

    monkeypatch.setattr(vdb_syncer, "vdb_engine", engine)
    monkeypatch.setattr(vdb_syncer, "SYNC_TARGETS", ["boom", "openssh"])

    def fake_query(product, *a, **k):
        if product == "boom":
            raise RuntimeError("NVD exploded")
        return [_cve("CVE-2024-7777", ve_="8.0")]

    monkeypatch.setattr(vdb_syncer, "query_nvd_for_product", fake_query)
    result = vdb_syncer.run_vdb_sync(limit=0)
    assert result["products"] == 1
    assert result["cves"] == 1
