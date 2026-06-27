"""
Guard tests for NetLogic Jobs & SSE streaming.

Covers the previously-unreviewed SSE generator / cancel / delete edits in
api/jobs/manager.py and api/routes/jobs.py:

  • SSE yields buffered events then closes on a terminal event.
  • The absolute cursor stays correct when the capped deque evicts old events
    mid-stream (no skip / dup / corruption of still-buffered events).
  • A disconnected/abandoned consumer does not hang or leak (sentinel + cancel
    both close the stream; CancelledError is swallowed).
  • Event history is capped at EVENT_CAP.
  • Cancel reaches terminal state, sets the stop flag, and the cancel route does
    NOT raise JobCancelled into the request handler (would be HTTP 500).
  • _maybe_evict respects TTL / MAX_JOBS and never evicts a running job.
  • Cross-org get / cancel / delete are denied (404); list is org-scoped.
  • Bad input is rejected (422); unauth is 401.

Offline only — the scan engine is never invoked (submit_scan is monkeypatched
where a route would otherwise dispatch).
"""

from __future__ import annotations

import asyncio
import time
import unittest

from api.jobs.manager import JobManager, ScanJob, JobCancelled, job_manager
from api.models.scan_request import ScanRequest


def _drain_async_gen(agen):
    """Run an async generator to exhaustion on a fresh loop; return yielded items."""
    loop = asyncio.new_event_loop()
    try:
        out = []

        async def pump():
            async for item in agen:
                out.append(item)

        loop.run_until_complete(asyncio.wait_for(pump(), timeout=5.0))
        return out
    finally:
        loop.close()


# ───────────────────────── ScanJob / push_event ──────────────────────────────


class TestPushEventCursor(unittest.TestCase):
    def _job(self):
        return ScanJob(job_id="j", config=ScanRequest(target="example.com"))

    def test_total_events_is_monotonic_under_cap(self):
        job = self._job()
        job.EVENT_CAP = 5
        for i in range(12):
            job.push_event({"type": "port", "n": i})
        # deque is capped...
        self.assertEqual(len(job.events), 5)
        # ...but the absolute counter keeps climbing.
        self.assertEqual(job._total_events, 12)
        # deque holds the newest 5 events.
        self.assertEqual([e["n"] for e in job.events], [7, 8, 9, 10, 11])

    def test_push_event_outside_scan_thread_does_not_raise(self):
        # Reproduces the cancel-route 500: _stop_flag set + push_event called on
        # the event-loop thread must NOT raise JobCancelled.
        job = self._job()
        job._stop_flag.set()

        async def call_on_loop():
            job.push_event({"type": "error", "message": "cancelled"})

        asyncio.new_event_loop().run_until_complete(call_on_loop())  # no raise == pass

    def test_push_event_on_worker_thread_raises(self):
        # On a plain thread (no running loop) cooperative cancellation still works.
        job = self._job()
        job._stop_flag.set()
        with self.assertRaises(JobCancelled):
            job.push_event({"type": "progress", "data": {"percent": 1}})

    def test_progress_updates_from_event(self):
        job = self._job()
        job.push_event({"type": "progress", "data": {"percent": 42.5}})
        self.assertEqual(job.progress, 42.5)


# ───────────────────────── SSE generator (_drain + _sse_generator) ────────────


class TestSSEGenerator(unittest.TestCase):
    def _job(self):
        return ScanJob(job_id="s", config=ScanRequest(target="example.com"))

    def test_replays_history_then_closes_on_terminal(self):
        from api.routes.jobs import _sse_generator

        job = self._job()
        job.status = "completed"  # already finished, queue never set
        job.push_event({"type": "port", "data": 1})
        job.push_event({"type": "port", "data": 2})
        job.push_event({"type": "done", "data": {"ok": True}})

        out = _drain_async_gen(_sse_generator(job))
        # 3 events delivered, stream closed after terminal "done".
        self.assertEqual(len(out), 3)
        self.assertIn('"type": "port"', out[0])
        self.assertIn('"type": "done"', out[-1])

    def test_cursor_correct_when_deque_evicts_midstream(self):
        # The core bug: drain part of history, evict past the cap, drain again.
        from api.routes.jobs import _drain

        job = self._job()
        job.EVENT_CAP = 5
        for i in range(5):
            job.push_event({"type": "port", "n": i})

        # First drain: consume all 5.
        items = _drain(job, 0)
        idx = items[-1][1]
        seen = [i[0] for i in items]
        self.assertEqual(idx, 5)
        self.assertEqual(len(seen), 5)

        # Push 5 more → deque evicts n=0..4, now holds n=5..9.
        for i in range(5, 10):
            job.push_event({"type": "port", "n": i})

        # Second drain from cursor 5 must yield exactly n=5..9 (no skip, no dup).
        items2 = _drain(job, idx)
        self.assertEqual(len(items2), 5)
        self.assertTrue(all(f'"n": {n}' in items2[k][0] for k, n in enumerate(range(5, 10))))
        self.assertEqual(items2[-1][1], 10)

    def test_cursor_clamps_when_consumer_falls_behind_cap(self):
        # Consumer at idx=0, but stream raced far past the cap before draining.
        from api.routes.jobs import _drain

        job = self._job()
        job.EVENT_CAP = 3
        for i in range(10):
            job.push_event({"type": "port", "n": i})

        # deque holds the newest 3 (n=7,8,9). A stale cursor of 0 must resume from
        # the oldest buffered event, not skip everything.
        items = _drain(job, 0)
        self.assertEqual(len(items), 3)
        self.assertIn('"n": 7', items[0][0])
        self.assertEqual(items[-1][1], 10)  # cursor advanced to absolute total

    def test_sentinel_closes_stream_no_hang(self):
        from api.routes.jobs import _sse_generator

        job = self._job()
        loop = asyncio.new_event_loop()
        try:
            job._loop = loop
            job._queue = asyncio.Queue(maxsize=100)
            # Pre-load one event + the sentinel so the generator drains and exits.
            job.push_event({"type": "port", "data": 1})
            job._queue.put_nowait("wake")
            job._queue.put_nowait(None)  # sentinel

            out = []

            async def pump():
                async for item in _sse_generator(job):
                    out.append(item)

            loop.run_until_complete(asyncio.wait_for(pump(), timeout=5.0))
        finally:
            loop.close()
        self.assertTrue(any('"type": "port"' in s for s in out))

    def test_disconnect_does_not_leak_or_hang(self):
        # Simulate client disconnect: aclose() raises GeneratorExit / CancelledError
        # into the awaiting generator; it must terminate cleanly.
        from api.routes.jobs import _sse_generator

        job = self._job()
        loop = asyncio.new_event_loop()
        try:
            job._loop = loop
            job._queue = asyncio.Queue(maxsize=100)

            agen = _sse_generator(job)

            async def scenario():
                # Start the generator; it will block on queue.get() (empty queue).
                task = asyncio.ensure_future(agen.__anext__())
                await asyncio.sleep(0.05)
                self.assertFalse(task.done())  # blocked, not spinning
                # Client disconnect → the in-flight await is cancelled. The
                # generator's `except CancelledError: return` must swallow it and
                # terminate cleanly (StopAsyncIteration on the next pull).
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, StopAsyncIteration):
                    pass
                # Generator should now be finished; aclose() is a clean no-op.
                await agen.aclose()

            loop.run_until_complete(asyncio.wait_for(scenario(), timeout=5.0))
        finally:
            loop.close()

    def test_queue_init_timeout_bails(self):
        from api.routes.jobs import _sse_generator

        job = self._job()
        job._queue = None  # never initialised
        # Shrink the wait budget so the test is fast.
        import api.routes.jobs as jobs_mod

        out = []
        loop = asyncio.new_event_loop()
        try:
            # Patch asyncio.sleep used inside the module to be instant.
            orig_sleep = asyncio.sleep

            async def fast_sleep(_):
                await orig_sleep(0)

            jobs_mod.asyncio.sleep = fast_sleep
            try:
                async def pump():
                    async for item in _sse_generator(job):
                        out.append(item)
                loop.run_until_complete(asyncio.wait_for(pump(), timeout=5.0))
            finally:
                jobs_mod.asyncio.sleep = orig_sleep
        finally:
            loop.close()
        self.assertTrue(any("initialisation timeout" in s for s in out))


# ───────────────────────── JobManager eviction ───────────────────────────────


class TestEviction(unittest.TestCase):
    def setUp(self):
        self.mgr = JobManager()
        self.mgr._jobs.clear()

    def _add(self, status, age_s=0.0, org="o"):
        job = ScanJob(job_id=f"j{len(self.mgr._jobs)}-{time.time()}",
                      config=ScanRequest(target="example.com"), org_id=org)
        job.status = status
        job.created_at = time.time() - age_s
        self.mgr._jobs[job.job_id] = job
        return job

    def test_ttl_evicts_old_terminal_spares_running(self):
        old_done = self._add("completed", age_s=self.mgr.JOB_TTL_SECONDS + 100)
        old_running = self._add("running", age_s=self.mgr.JOB_TTL_SECONDS + 100)
        fresh = self._add("completed", age_s=10)
        self.mgr._maybe_evict()
        self.assertNotIn(old_done.job_id, self.mgr._jobs)     # evicted (TTL)
        self.assertIn(old_running.job_id, self.mgr._jobs)     # spared (running)
        self.assertIn(fresh.job_id, self.mgr._jobs)           # spared (fresh)

    def test_maxjobs_evicts_oldest_terminal_only(self):
        self.mgr.MAX_JOBS = 5
        running = [self._add("running", age_s=1000 + i) for i in range(3)]
        terminal = [self._add("completed", age_s=500 + i) for i in range(4)]
        # 7 jobs, cap 5 → must drop 3 oldest *terminal* jobs, never the running.
        self.mgr._maybe_evict()
        for r in running:
            self.assertIn(r.job_id, self.mgr._jobs)
        survivors = set(self.mgr._jobs)
        evicted = [t for t in terminal if t.job_id not in survivors]
        self.assertEqual(len(evicted), 3)
        # Evicted ones are the oldest terminal jobs.
        oldest_three = sorted(terminal, key=lambda j: j.created_at)[:3]
        self.assertEqual({t.job_id for t in evicted}, {t.job_id for t in oldest_three})

    def test_evict_all_running_does_not_crash(self):
        self.mgr.MAX_JOBS = 2
        for _ in range(5):
            self._add("running", age_s=10)
        # No terminal jobs to evict — must not raise, just stay over cap.
        self.mgr._maybe_evict()
        self.assertEqual(len(self.mgr._jobs), 5)


# ───────────────────────── Route / org-scoping (HTTP) ─────────────────────────


class TestJobRoutesHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from starlette.testclient import TestClient
        from api.main import create_app
        from api.auth.jwt_handler import create_token

        cls.app = create_app()
        cls.client = TestClient(cls.app)
        cls.tok_a = create_token(org_id="org-a", sub="user-a")
        cls.tok_b = create_token(org_id="org-b", sub="user-b")

    def _h(self, tok):
        return {"Authorization": f"Bearer {tok}"}

    def setUp(self):
        # Patch dispatch so POST /jobs never touches the scan engine / agents.
        import api.routes.jobs as jr

        async def _noop_submit(job):
            job._loop = asyncio.get_running_loop()
            job._queue = asyncio.Queue(maxsize=10)

        self._orig_submit = jr.submit_scan
        jr.submit_scan = _noop_submit
        # Relax the rate limiter so repeated test POSTs don't 429.
        from api.auth.rate_limit import jobs_limiter
        jobs_limiter.reset("org-a")
        jobs_limiter.reset("org-b")

    def tearDown(self):
        import api.routes.jobs as jr
        jr.submit_scan = self._orig_submit

    def _create(self, tok, target="scanme.example.com"):
        r = self.client.post("/v1/jobs", json={"target": target}, headers=self._h(tok))
        self.assertEqual(r.status_code, 202, r.text)
        return r.json()["job_id"]

    def test_unauthenticated_rejected(self):
        self.assertEqual(self.client.get("/v1/jobs").status_code, 401)

    def test_bad_input_rejected(self):
        r = self.client.post("/v1/jobs", json={"target": ""}, headers=self._h(self.tok_a))
        self.assertEqual(r.status_code, 422)
        r2 = self.client.post("/v1/jobs", json={}, headers=self._h(self.tok_a))
        self.assertEqual(r2.status_code, 422)

    def test_create_and_get_own_job(self):
        jid = self._create(self.tok_a)
        r = self.client.get(f"/v1/jobs/{jid}", headers=self._h(self.tok_a))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["job_id"], jid)

    def test_cross_org_get_denied(self):
        jid = self._create(self.tok_a)
        r = self.client.get(f"/v1/jobs/{jid}", headers=self._h(self.tok_b))
        self.assertEqual(r.status_code, 404)

    def test_cross_org_cancel_denied(self):
        jid = self._create(self.tok_a)
        r = self.client.post(f"/v1/jobs/{jid}/cancel", headers=self._h(self.tok_b))
        self.assertEqual(r.status_code, 404)
        # Job untouched for the real owner.
        owner = job_manager.get(jid, org_id="org-a")
        self.assertNotEqual(owner.status, "cancelled")

    def test_cross_org_delete_denied(self):
        jid = self._create(self.tok_a)
        r = self.client.delete(f"/v1/jobs/{jid}", headers=self._h(self.tok_b))
        self.assertEqual(r.status_code, 404)
        self.assertIsNotNone(job_manager.get(jid, org_id="org-a"))

    def test_cancel_reaches_terminal_no_500(self):
        jid = self._create(self.tok_a)
        r = self.client.post(f"/v1/jobs/{jid}/cancel", headers=self._h(self.tok_a))
        self.assertEqual(r.status_code, 200, r.text)  # not 500
        body = r.json()
        self.assertTrue(body["cancelled"])
        self.assertEqual(body["status"], "cancelled")
        job = job_manager.get(jid, org_id="org-a")
        self.assertEqual(job.status, "cancelled")
        self.assertTrue(job._stop_flag.is_set())

    def test_cancel_already_terminal_is_noop(self):
        jid = self._create(self.tok_a)
        self.client.post(f"/v1/jobs/{jid}/cancel", headers=self._h(self.tok_a))
        r2 = self.client.post(f"/v1/jobs/{jid}/cancel", headers=self._h(self.tok_a))
        self.assertEqual(r2.status_code, 200)
        self.assertFalse(r2.json()["cancelled"])

    def test_list_is_org_scoped(self):
        a = self._create(self.tok_a)
        b = self._create(self.tok_b)
        ids_a = {j["job_id"] for j in self.client.get(
            "/v1/jobs", headers=self._h(self.tok_a)).json()}
        ids_b = {j["job_id"] for j in self.client.get(
            "/v1/jobs", headers=self._h(self.tok_b)).json()}
        self.assertIn(a, ids_a)
        self.assertNotIn(b, ids_a)
        self.assertIn(b, ids_b)
        self.assertNotIn(a, ids_b)

    def test_delete_own_running_job_signals_stop(self):
        jid = self._create(self.tok_a)
        job = job_manager.get(jid, org_id="org-a")
        job.status = "running"
        r = self.client.delete(f"/v1/jobs/{jid}", headers=self._h(self.tok_a))
        self.assertEqual(r.status_code, 204)
        self.assertTrue(job._stop_flag.is_set())
        self.assertIsNone(job_manager.get(jid, org_id="org-a"))

    def test_get_missing_job_404(self):
        r = self.client.get("/v1/jobs/does-not-exist", headers=self._h(self.tok_a))
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
