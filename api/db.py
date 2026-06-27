"""
NetLogic — PostgreSQL layer (opt-in).

The whole module is INERT unless NETLOGIC_DATABASE_URL is set: is_enabled() is
False, psycopg is never imported, and callers fall back to the in-memory stores.
This keeps local/desktop use and the test suite working with zero DB and zero new
dependencies, while a SaaS deployment flips it on with one env var.

  NETLOGIC_DATABASE_URL   e.g. postgresql://user:pass@host:5432/netlogic

psycopg (and optionally psycopg_pool) are imported lazily so they're only needed
when the DB is actually configured.
"""

from __future__ import annotations

import logging
import os
import threading
from contextlib import contextmanager
from pathlib import Path

log = logging.getLogger("netlogic.db")

_MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "db" / "migrations"

_pool = None
_pool_lock = threading.Lock()


def database_url() -> str:
    return (os.environ.get("NETLOGIC_DATABASE_URL") or "").strip()


def is_enabled() -> bool:
    return bool(database_url())


def _get_pool():
    """Lazy connection pool. Falls back to None if psycopg_pool isn't installed
    (then connection() opens a short-lived connection per call)."""
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                try:
                    from psycopg_pool import ConnectionPool  # noqa: PLC0415
                    _pool = ConnectionPool(
                        database_url(), min_size=1, max_size=10, open=True,
                        kwargs={"autocommit": True},
                    )
                except ImportError:
                    _pool = False  # sentinel: no pool available
    return _pool or None


@contextmanager
def connection():
    """Yield a psycopg connection (autocommit). Uses the pool when available."""
    pool = _get_pool()
    if pool is not None:
        with pool.connection() as conn:
            yield conn
        return
    import psycopg  # noqa: PLC0415 — lazy, only when DB enabled and no pool
    conn = psycopg.connect(database_url(), autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


def _split_sql(text: str) -> list[str]:
    """Split a migration file into individual statements on ';'.

    Comment- and string-literal-aware: a ';' inside a ``--`` line comment or a
    ``'...'`` string literal does NOT end a statement. (A naive split broke on a
    header comment containing a semicolon — "owned by the IdP; we only verify…" —
    turning the comment tail into a bogus statement.) Bare BEGIN/COMMIT are
    dropped — the runner owns the transaction. Block comments (/* */) are not
    used by our migrations and are not handled.
    """
    stmts: list[str] = []
    buf: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            buf.append(ch)
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":   # escaped '' inside literal
                    buf.append(text[i + 1])
                    i += 2
                    continue
                in_str = False
            i += 1
            continue
        if ch == "'":
            in_str = True
            buf.append(ch)
        elif ch == "-" and i + 1 < n and text[i + 1] == "-":
            j = text.find("\n", i)               # line comment → skip to EOL
            if j == -1:
                break
            i = j
            continue
        elif ch == ";":
            stmts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    if buf:
        stmts.append("".join(buf))

    out: list[str] = []
    for raw in stmts:
        s = raw.strip()
        if not s or s.upper() in ("BEGIN", "COMMIT"):
            continue
        out.append(s)
    return out


def apply_migrations() -> list[str]:
    """Apply any unapplied .sql migrations in db/migrations, in filename order.

    Each migration runs in its own transaction (atomic). Returns the names applied
    this run. No-op (returns []) when the DB is disabled.
    """
    if not is_enabled():
        return []
    import psycopg  # noqa: PLC0415

    applied: list[str] = []
    with psycopg.connect(database_url()) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "filename text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
            )
            conn.commit()
            cur.execute("SELECT filename FROM schema_migrations")
            done = {r[0] for r in cur.fetchall()}

        for path in sorted(_MIGRATIONS_DIR.glob("*.sql")):
            if path.name in done:
                continue
            try:
                with conn.cursor() as cur:
                    for stmt in _split_sql(path.read_text(encoding="utf-8")):
                        cur.execute(stmt)
                    cur.execute(
                        "INSERT INTO schema_migrations (filename) VALUES (%s)", (path.name,)
                    )
                conn.commit()
                applied.append(path.name)
                log.info("Applied migration %s", path.name)
            except Exception:
                conn.rollback()
                log.exception("Migration %s failed — rolled back", path.name)
                raise
    return applied
