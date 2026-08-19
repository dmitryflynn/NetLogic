"""
NetLogic — JWT revocation denylist.

Supports emergency revocation of NetLogic-issued HS256 JWTs before they expire.
Uses Postgres ``revoked_tokens`` when ``NETLOGIC_DATABASE_URL`` is set; otherwise
an in-process denylist (suitable for desktop / tests).
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("netlogic.token_revocation")

_lock = threading.Lock()
_memory: dict[str, float] = {}  # jti → exp (unix seconds)
_last_sweep = 0.0
_SWEEP_INTERVAL = 60.0


def _sweep_memory(now: float | None = None) -> None:
    global _last_sweep
    now = now if now is not None else time.time()
    if now - _last_sweep < _SWEEP_INTERVAL:
        return
    stale = [jti for jti, exp in _memory.items() if exp <= now]
    for jti in stale:
        del _memory[jti]
    _last_sweep = now


def revoke_token(jti: str, expires_at: float) -> None:
    """Add a token id to the denylist until *expires_at* (unix seconds)."""
    if not jti:
        return
    with _lock:
        _memory[jti] = float(expires_at)
        _sweep_memory()

    from api import db  # noqa: PLC0415
    if not db.is_enabled():
        return
    try:
        exp_dt = datetime.fromtimestamp(expires_at, tz=timezone.utc)
        with db.connection() as conn:
            conn.execute(
                "INSERT INTO revoked_tokens (jti, expires_at) VALUES (%s, %s) "
                "ON CONFLICT (jti) DO UPDATE SET expires_at = EXCLUDED.expires_at",
                (jti, exp_dt),
            )
    except Exception as exc:  # noqa: BLE001 — denylist is best-effort on DB failure
        log.warning("failed to persist token revocation for jti=%s: %s", jti[:8], exc)


def is_token_revoked(jti: Optional[str], exp: Optional[float | int] = None) -> bool:
    """Return True if *jti* is on the denylist and not yet expired."""
    if not jti:
        return False
    now = time.time()
    with _lock:
        _sweep_memory(now)
        mem_exp = _memory.get(jti)
        if mem_exp is not None:
            if mem_exp > now:
                return True
            del _memory[jti]

    from api import db  # noqa: PLC0415
    if not db.is_enabled():
        return False
    try:
        with db.connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM revoked_tokens WHERE jti = %s AND expires_at > now()",
                (jti,),
            ).fetchone()
            return row is not None
    except Exception as exc:  # noqa: BLE001 — fail open on DB outage (logged)
        log.warning("token revocation lookup failed: %s", exc)
        return False


def reset_for_tests() -> None:
    """Clear the in-memory denylist (tests only)."""
    global _last_sweep
    with _lock:
        _memory.clear()
        _last_sweep = 0.0
