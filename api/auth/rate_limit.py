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

    def __init__(self, max_calls: int, window_seconds: float) -> None:
        self._max_calls = max_calls
        self._window    = window_seconds
        self._buckets:  Dict[str, deque] = {}
        self._lock      = threading.Lock()

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
            if len(bucket) >= self._max_calls:
                return False
            bucket.append(now)
            return True

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
