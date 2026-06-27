"""
Pytest session bootstrap — test isolation for NetLogic.

Several modules bind their on-disk state directory at import time:
  • api/agents/registry.py   → $NETLOGIC_SCANS_DIR/agents.json
  • api/storage/json_store.py → $NETLOGIC_SCANS_DIR/scans/*.json
  • src/epss.py, src/vdb_engine.py → $NETLOGIC_DATA_DIR caches

Without this file the test suite wrote into the developer's real ~/.netlogic,
leaving behind dozens of phantom agents (test-host, agent-a, …) that eventually
tripped the per-org agent cap and broke unrelated tests. conftest.py is imported
by pytest BEFORE any test module (and therefore before those api/src imports), so
forcing the env vars here relocates all state into a fresh temp dir that is
removed when the session ends.
"""
import atexit
import os
import shutil
import tempfile

import pytest

_TEST_STATE_DIR = tempfile.mkdtemp(prefix="netlogic-test-")
os.environ["NETLOGIC_SCANS_DIR"] = _TEST_STATE_DIR
os.environ["NETLOGIC_DATA_DIR"] = _TEST_STATE_DIR

# Provide a deterministic test license so the LicenseMiddleware lets requests
# through to the auth/route logic under test. Previously the suite implicitly
# depended on the developer's real ~/.netlogic/secrets.json containing a license;
# now that state is isolated to the temp dir, so set it explicitly here. Tests
# that exercise the license validator itself pass their own keys and are unaffected.
os.environ.setdefault("NETLOGIC_LICENSE_KEY", "NL-TEST-LICENSE-PRO")
# Without these the auth modules import with empty default secrets, and
# test_auth_multitenancy (unittest.TestCase, no monkeypatch) can't create
# admin-level API keys because verify_admin("") always fails.
os.environ.setdefault("NETLOGIC_JWT_SECRET", "test-session-jwt-secret-0123456789ab")
os.environ.setdefault("NETLOGIC_ADMIN_KEY", "test-admin-key-for-pytest-session-0123")

atexit.register(lambda: shutil.rmtree(_TEST_STATE_DIR, ignore_errors=True))


@pytest.fixture(autouse=True)
def _reset_global_rate_limiters():
    """Clear the process-global rate limiters + ban list before each test.

    The pre-configured limiters in api.auth.rate_limit are module-level singletons
    shared across the whole pytest process. Their sliding windows are 60s+, longer
    than a full suite run, so without a reset, calls accumulate across unrelated
    tests and a later test can spuriously hit a 429/ban. Resetting per test keeps
    rate-limit behavior deterministic and isolated.
    """
    try:
        from api.auth import rate_limit as _rl
        for _obj in vars(_rl).values():
            if isinstance(_obj, _rl.RateLimiter):
                with _obj._lock:
                    _obj._buckets.clear()
        with _rl.ban_list._lock:
            _rl.ban_list._banned_ips.clear()
    except Exception:
        pass
    yield
