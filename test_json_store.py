"""
Offline unit tests for api/storage/json_store.py (the JSON-file scan store).

Covers: save->read round-trip, path-traversal containment, atomic writes
(tmp+replace, no leftover .tmp), fail-soft on OSError/disk-full and
non-serializable fields, corrupt-file load handling, and UTF-8 round-trips.

All tests are offline and confined to tmp_path; none touch ~/.netlogic.
"""

from __future__ import annotations

import asyncio
import json
import os
import time

import pytest

from api.storage.json_store import JsonScanStore


def _store(tmp_path) -> JsonScanStore:
    return JsonScanStore(str(tmp_path / "scans"))


def _files(store) -> list[str]:
    return os.listdir(store.directory)


# ── Round-trip ────────────────────────────────────────────────────────────────

def test_save_get_round_trip(tmp_path):
    store = _store(tmp_path)
    rec = {"job_id": "abc", "status": "done", "findings": [1, 2, 3]}
    asyncio.run(store.save_scan("abc", rec))
    got = asyncio.run(store.get_scan("abc"))
    assert got == rec


def test_get_missing_returns_none(tmp_path):
    store = _store(tmp_path)
    assert asyncio.run(store.get_scan("does-not-exist")) is None


def test_list_newest_first(tmp_path):
    store = _store(tmp_path)
    asyncio.run(store.save_scan("one", {"n": 1}))
    # bump mtime ordering deterministically
    os.utime(os.path.join(store.directory, "one.json"), (1, 1))
    asyncio.run(store.save_scan("two", {"n": 2}))
    os.utime(os.path.join(store.directory, "two.json"), (10, 10))
    out = asyncio.run(store.list_scans())
    assert [r["n"] for r in out] == [2, 1]


# ── Path traversal containment ─────────────────────────────────────────────────

@pytest.mark.parametrize("bad_id", [
    "../escape",
    "..\\escape",
    "foo/bar",
    "foo\\bar",
    "../../etc/passwd",
    "a/../../b",
    "with\x00null",
    "..",
    ".",
    "",
])
def test_traversal_save_cannot_escape(tmp_path, bad_id):
    store = _store(tmp_path)
    # Should be a no-op, never raise, and never create files outside the dir.
    asyncio.run(store.save_scan(bad_id, {"evil": True}))
    # Nothing written anywhere under the parent tmp tree except (possibly) inside store.directory.
    for root, _dirs, fnames in os.walk(tmp_path):
        for fn in fnames:
            full = os.path.abspath(os.path.join(root, fn))
            assert os.path.dirname(full) == store.directory, f"file escaped: {full}"


def test_traversal_absolute_path_id(tmp_path):
    store = _store(tmp_path)
    target = tmp_path / "pwned"  # absolute path as a job_id
    asyncio.run(store.save_scan(str(target), {"evil": True}))
    assert not (tmp_path / "pwned.json").exists()
    assert _files(store) == []


def test_write_direct_outside_dir_refused(tmp_path):
    # JobManager calls _write directly with a pre-built path; it must still
    # refuse paths outside the scans directory.
    store = _store(tmp_path)
    outside = str(tmp_path / "outside.json")
    store._write(outside, {"evil": True})
    assert not os.path.exists(outside)


# ── Atomic write ────────────────────────────────────────────────────────────────

def test_atomic_no_tmp_leftover(tmp_path):
    store = _store(tmp_path)
    asyncio.run(store.save_scan("job1", {"ok": True}))
    leftovers = [f for f in _files(store) if f.endswith(".tmp")]
    assert leftovers == []
    assert _files(store) == ["job1.json"]


def test_write_uses_tmp_then_replace(tmp_path, monkeypatch):
    store = _store(tmp_path)
    seen = {}

    real_replace = os.replace

    def spy_replace(src, dst):
        seen["src"] = src
        seen["dst"] = dst
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", spy_replace)
    store._write(os.path.join(store.directory, "j.json"), {"x": 1})
    assert seen["src"].endswith(".tmp")
    assert seen["dst"].endswith("j.json")


def test_concurrent_writes_no_corruption(tmp_path):
    store = _store(tmp_path)

    async def hammer():
        await asyncio.gather(*[
            store.save_scan("shared", {"writer": i, "data": "x" * 1000})
            for i in range(20)
        ])

    asyncio.run(hammer())
    # File must be valid JSON (one writer won), and no tmp files leaked.
    got = asyncio.run(store.get_scan("shared"))
    assert isinstance(got, dict) and "writer" in got
    assert [f for f in _files(store) if f.endswith(".tmp")] == []


# ── Fail-soft ───────────────────────────────────────────────────────────────────

def test_disk_full_fails_soft(tmp_path, monkeypatch):
    store = _store(tmp_path)

    def boom(*_a, **_k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("builtins.open", boom)
    # Must not raise.
    store._write(os.path.join(store.directory, "j.json"), {"x": 1})
    # No file and no tmp leftover.
    assert _files(store) == []


def test_non_serializable_field_fails_soft(tmp_path):
    store = _store(tmp_path)

    class Weird:
        pass

    # default=str handles most things, but a key that isn't str/int and a
    # circular structure both raise inside json.dump -> must fail soft.
    circular: dict = {}
    circular["self"] = circular
    store._write(os.path.join(store.directory, "j.json"), circular)
    assert [f for f in _files(store) if f.endswith(".tmp")] == []
    assert not os.path.exists(os.path.join(store.directory, "j.json"))


def test_save_scan_swallows_write_errors(tmp_path, monkeypatch):
    # End-to-end: a genuine disk error during the async save path is contained
    # by _write and never propagates out of save_scan (would crash a scan).
    store = _store(tmp_path)

    def boom(*_a, **_k):
        raise OSError("disk")

    monkeypatch.setattr("builtins.open", boom)
    asyncio.run(store.save_scan("jx", {"a": 1}))  # must not raise
    assert not os.path.exists(os.path.join(store.directory, "jx.json"))


# ── Corrupt / partial load ──────────────────────────────────────────────────────

def test_corrupt_file_load_returns_none(tmp_path):
    store = _store(tmp_path)
    path = os.path.join(store.directory, "bad.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{ this is not valid json ")
    assert asyncio.run(store.get_scan("bad")) is None


def test_corrupt_file_skipped_in_list(tmp_path):
    store = _store(tmp_path)
    asyncio.run(store.save_scan("good", {"ok": 1}))
    with open(os.path.join(store.directory, "bad.json"), "w", encoding="utf-8") as fh:
        fh.write("not json")
    out = asyncio.run(store.list_scans())
    assert out == [{"ok": 1}]


def test_oversized_file_skipped(tmp_path, monkeypatch):
    store = _store(tmp_path)
    asyncio.run(store.save_scan("big", {"ok": 1}))
    monkeypatch.setattr("api.storage.json_store._MAX_FILE_BYTES", 1)
    assert asyncio.run(store.get_scan("big")) is None


# ── UTF-8 ───────────────────────────────────────────────────────────────────────

def test_utf8_round_trip(tmp_path):
    store = _store(tmp_path)
    rec = {"host": "máquina-ñoño", "note": "日本語テスト", "emoji": "🚨🔐"}
    asyncio.run(store.save_scan("u8", rec))
    # Bytes on disk are UTF-8 (not \u-escaped ASCII).
    with open(os.path.join(store.directory, "u8.json"), "rb") as fh:
        raw = fh.read()
    assert "日本語テスト".encode("utf-8") in raw
    assert asyncio.run(store.get_scan("u8")) == rec


# ── .tmp cleanup ──────────────────────────────────────────────────────────────────

def test_stale_tmp_cleaned_on_list(tmp_path):
    store = _store(tmp_path)
    asyncio.run(store.save_scan("real", {"ok": 1}))
    stale = os.path.join(store.directory, "real.json.deadbeef.tmp")
    with open(stale, "w", encoding="utf-8") as fh:
        fh.write("{}")
    # Make it look older than 60 s so the stale-cleanup removes it.
    old = time.time() - 120
    os.utime(stale, (old, old))
    asyncio.run(store.list_scans())
    assert not os.path.exists(stale)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
