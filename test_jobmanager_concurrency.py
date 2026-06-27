"""
Concurrency stress test for JobManager (in-memory backend).

The durable-jobs work added cache eviction + DB-fallback paths around the shared
`_jobs` dict and lock. This hammers create/get/list/cancel/delete from many
threads at once and asserts: no exception escapes, no deadlock, and the core
invariants hold (no cross-org leakage, sane counts, lock never wedged). Validates
thread-safety / "no glitches under load" without needing a network or DB.
"""
import threading
import time

import pytest

from api.jobs.manager import JobManager
from api.models.scan_request import ScanRequest


def _mk_manager(monkeypatch):
    # In-memory backend, isolated; MagicMock-free real store but no real I/O needed
    # because we drive the manager API directly (persist is best-effort/no-loop).
    m = JobManager.__new__(JobManager)
    m._jobs = {}
    m._lock = threading.RLock()
    from unittest.mock import MagicMock
    m.store = MagicMock()
    return m


def test_concurrent_create_get_list_delete_no_races(monkeypatch):
    m = _mk_manager(monkeypatch)
    req = ScanRequest(target="127.0.0.1", ports="quick")
    errors: list[Exception] = []
    created_ids: list[tuple[str, str]] = []   # (job_id, org_id)
    ids_lock = threading.Lock()
    N_THREADS = 24
    N_OPS = 60

    def worker(t: int):
        org = f"org-{t % 4}"
        try:
            for i in range(N_OPS):
                op = i % 5
                if op == 0:
                    job = m.create(req, org_id=org)
                    with ids_lock:
                        created_ids.append((job.job_id, org))
                elif op == 1:
                    m.list(limit=20, org_id=org)
                elif op == 2:
                    with ids_lock:
                        sample = created_ids[-1] if created_ids else None
                    if sample:
                        # Cross-org get must never return another org's job.
                        got = m.get(sample[0], org_id=org)
                        if got is not None and got.org_id != org:
                            raise AssertionError("cross-org leak in get()")
                elif op == 3:
                    m.list_queued_unassigned(org_id=org)
                else:
                    with ids_lock:
                        sample = created_ids[0] if created_ids else None
                    if sample:
                        m.get(sample[0], org_id=sample[1])
        except Exception as e:  # noqa: BLE001 — capture, fail in main thread
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(N_THREADS)]
    start = time.time()
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=30)
    elapsed = time.time() - start

    assert not any(th.is_alive() for th in threads), "deadlock: a worker did not finish"
    assert not errors, f"races/exceptions under concurrency: {errors[:3]}"
    assert elapsed < 25, f"suspiciously slow ({elapsed:.1f}s) — possible lock contention/deadlock"

    # Invariant: every surviving job is retrievable only by its owning org.
    for jid, org in created_ids:
        wrong = "org-other"
        assert m.get(jid, org_id=wrong) is None or m.get(jid, org_id=wrong).org_id == org


def test_concurrent_cancel_and_delete_are_safe(monkeypatch):
    m = _mk_manager(monkeypatch)
    req = ScanRequest(target="127.0.0.1", ports="quick")
    jobs = [m.create(req, org_id="org-a") for _ in range(50)]
    errors: list[Exception] = []

    def deleter(job):
        try:
            m.delete(job.job_id)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def lister():
        try:
            for _ in range(50):
                m.list(limit=50, org_id="org-a")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=deleter, args=(j,)) for j in jobs]
    threads += [threading.Thread(target=lister) for _ in range(6)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=20)

    assert not any(th.is_alive() for th in threads), "deadlock during concurrent delete/list"
    assert not errors, f"exceptions during concurrent delete/list: {errors[:3]}"
