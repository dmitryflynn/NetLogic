"""
NetLogic — In-memory sliding-window rate limiter.

No external dependencies.  Uses collections.deque for O(1) amortised
operations and threading.Lock for thread safety.

Usage
─────
    from api.auth.rate_limit import RateLimiter

    _limiter = RateLimiter(max_calls=10, window_seconds=60)

    # In a FastAPI dependency or middleware:
    key = request.client.host
    if not _limiter.allow(key):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

Public API
──────────
  RateLimiter(max_calls, window_seconds)
  .allow(key: str) → bool      # True = allowed, False = rate-limited
  .reset(key: str) → None      # For testing only
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Dict


class RateLimiter:
    """Sliding-window rate limiter keyed by an arbitrary string."""

    # Run a sweep of stale (empty) buckets at most this often, to bound the
    # cost of cleanup while keeping the dict from growing without limit.
    _SWEEP_INTERVAL_SECONDS = 60.0

    def __init__(self, max_calls: int, window_seconds: float) -> None:
        self._max_calls = max_calls
        self._window    = window_seconds
        self._buckets:  Dict[str, deque] = {}
        self._lock      = threading.Lock()
        self._last_sweep = time.monotonic()

    def allow(self, key: str) -> bool:
        """Return True if the request is within the allowed rate, False otherwise."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = deque()
            bucket = self._buckets[key]
            # Evict timestamps outside the window.
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            allowed = len(bucket) < self._max_calls
            if allowed:
                bucket.append(now)
            # Periodically evict keys whose buckets are fully expired. Without
            # this, a key-rotating client (e.g. spoofed source IPs / agent_ids)
            # grows _buckets without bound — an unbounded-memory DoS vector.
            if now - self._last_sweep >= self._SWEEP_INTERVAL_SECONDS:
                self._sweep(cutoff)
                self._last_sweep = now
            elif not bucket:
                # Fast path: never leave the just-touched key empty in the dict.
                del self._buckets[key]
            return allowed

    def _sweep(self, cutoff: float) -> None:
        """Drop keys whose every timestamp has aged out. Caller holds the lock."""
        stale = []
        for k, b in self._buckets.items():
            while b and b[0] <= cutoff:
                b.popleft()
            if not b:
                stale.append(k)
        for k in stale:
            del self._buckets[k]

    def reset(self, key: str) -> None:
        """Clear all recorded timestamps for a key (testing helper)."""
        with self._lock:
            self._buckets.pop(key, None)


# ── Pre-configured limiters ───────────────────────────────────────────────────

# POST /auth/token — 10 requests per minute per IP
token_limiter = RateLimiter(max_calls=10, window_seconds=60)

# POST /agents/register — 5 requests per hour per IP
register_limiter = RateLimiter(max_calls=5, window_seconds=3600)

# POST /agents/{id}/heartbeat — 3 per minute per agent_id
heartbeat_limiter = RateLimiter(max_calls=3, window_seconds=60)

# POST /agents/{id}/tasks/{job_id}/events — 60 per minute per agent_id
events_limiter = RateLimiter(max_calls=60, window_seconds=60)

# POST /jobs — 30 per minute per org_id
jobs_limiter = RateLimiter(max_calls=30, window_seconds=60)

# Job control/stream ops (stream, cancel, delete) — 60 per minute per org_id.
# Generous enough for normal dashboard use (one SSE stream per open job, rare
# cancel/delete) while capping abusive repeated opens of the SSE endpoint.
jobs_control_limiter = RateLimiter(max_calls=60, window_seconds=60)

# POST /v1/jobs — 10 per minute per org_id (stricter for API)
jobs_org_limiter = RateLimiter(max_calls=10, window_seconds=60)

# POST /v1/agents/{id}/tasks — 20 per minute per agent_id
agent_tasks_limiter = RateLimiter(max_calls=20, window_seconds=60)

# POST /v1/license/activate — 3 per hour per IP
license_activate_limiter = RateLimiter(max_calls=3, window_seconds=3600)

# /v1/settings/* — 20 per minute per org_id (save/test AI config)
settings_limiter = RateLimiter(max_calls=20, window_seconds=60)

# Token exchange failures — 5 per 10 minutes per IP (after which IP is banned)
token_fail_limiter = RateLimiter(max_calls=5, window_seconds=600)

# Admin key-management endpoints (/auth/keys) — 10 per minute per IP. Throttles
# brute-forcing of the admin credential, which is otherwise unthrottled.
admin_limiter = RateLimiter(max_calls=10, window_seconds=60)

# ── IP Ban List for Repeated Violations ────────────────────────────────────────

class RateLimitBanList:
    """Track and ban IPs that repeatedly exceed rate limits."""

    def __init__(self) -> None:
        self._banned_ips: dict[str, float] = {}  # ip -> ban_until_timestamp
        self._lock = threading.Lock()

    def check_ban(self, ip: str) -> bool:
        """Check if IP is currently banned."""
        with self._lock:
            if ip in self._banned_ips:
                if time.monotonic() < self._banned_ips[ip]:
                    return True
                else:
                    # Ban expired, remove it
                    del self._banned_ips[ip]
        return False

    def add_ban(self, ip: str, duration_hours: int = 24) -> None:
        """Ban IP for specified duration."""
        with self._lock:
            now = time.monotonic()
            # Opportunistically evict expired bans so the dict can't grow
            # unboundedly from churned/expired entries that are never re-checked.
            expired = [k for k, until in self._banned_ips.items() if until <= now]
            for k in expired:
                del self._banned_ips[k]
            self._banned_ips[ip] = now + (duration_hours * 3600)

    def remove_ban(self, ip: str) -> None:
        """Remove IP from ban list (for admin use)."""
        with self._lock:
            self._banned_ips.pop(ip, None)

# Global ban list instance
ban_list = RateLimitBanList()
