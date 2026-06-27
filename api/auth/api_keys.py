"""
NetLogic — API key store.

API keys are the long-lived credentials issued to organisations.  Exchanging
an API key for a short-lived JWT (via POST /auth/token) is the recommended
flow for all API consumers.

Storage
───────
Keys are kept in memory.  On startup the store is seeded from the environment:

    NETLOGIC_API_KEYS=key1:org_id1,key2:org_id2,...

Keys created at runtime are added to the in-memory store only; they are NOT
persisted across restarts unless the operator also sets the env var.  Phase 4
will add database-backed persistence.

Admin operations
────────────────
Creating and revoking keys requires the admin credential:

    NETLOGIC_ADMIN_KEY=<secret>          (default: "admin-changeme")

Public API
──────────
  api_key_store.lookup(key)   → Optional[str]   — org_id or None
  api_key_store.create(org_id) → str            — new key (UUID hex)
  api_key_store.revoke(key)   → bool
  api_key_store.list_keys()   → list[dict]       — [{key_masked, org_id}]
  verify_admin(key)            → bool
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from typing import Optional

log = logging.getLogger(__name__)

# Admin key length below which we consider the credential too weak for production.
ADMIN_KEY_MIN_LENGTH = 32

# Placeholder values that must never be accepted as a real admin credential.
INSECURE_ADMIN_KEYS = {"", "admin-changeme", "change-me-admin-key"}


def _get_admin_key() -> str:
    """Resolve the admin key from the environment WITHOUT terminating the process.

    Importing this module must never call sys.exit() — doing so makes the entire
    API (and the test suite) unimportable when the env var is absent. Weakness is
    surfaced two ways instead: a startup warning here, and a fail-closed
    verify_admin() that rejects all auth while the key is missing/insecure. Use
    require_strong_admin_key() at server startup to hard-enforce a strong key.
    """
    key = os.environ.get("NETLOGIC_ADMIN_KEY", "")
    if not key or key in INSECURE_ADMIN_KEYS:
        log.warning(
            "NETLOGIC_ADMIN_KEY is unset or a known placeholder — admin endpoints "
            "are DISABLED until a strong key is set. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    elif len(key) < ADMIN_KEY_MIN_LENGTH:
        log.warning(
            "NETLOGIC_ADMIN_KEY is shorter than %d characters (got %d) — "
            "use a stronger secret in production.", ADMIN_KEY_MIN_LENGTH, len(key),
        )
    return key


ADMIN_KEY: str = _get_admin_key()


def require_strong_admin_key() -> None:
    """Enforce a production-grade admin key. Call this at server startup.

    Raises RuntimeError (never sys.exit) so the caller decides how to react —
    e.g. abort boot in production, or tolerate it in tests/dev.
    """
    key = ADMIN_KEY
    if not key or key in INSECURE_ADMIN_KEYS:
        raise RuntimeError(
            "NETLOGIC_ADMIN_KEY must be set to a strong secret. Generate one with: "
            'python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    if len(key) < ADMIN_KEY_MIN_LENGTH:
        raise RuntimeError(
            f"NETLOGIC_ADMIN_KEY must be at least {ADMIN_KEY_MIN_LENGTH} characters "
            f"(got {len(key)})."
        )


class ApiKeyStore:
    """API key → org_id store, thread-safe and HASHED at rest.

    The plaintext key only ever exists transiently: it's returned once from
    create() and lives in the caller's request body during lookup(). At rest we
    keep only sha256(key) and a short non-secret display hint, so a memory dump,
    log of the store, or leaked env never exposes a usable credential. API keys
    are high-entropy random tokens (uuid4 hex), so a plain SHA-256 — not a slow
    password hash — is the right primitive: there is nothing to brute-force.
    """

    @staticmethod
    def _hash(key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    @staticmethod
    def _hint(key: str) -> str:
        """First 8 chars — a non-secret identifier for safe display/audit."""
        return key[:8]

    def __init__(self) -> None:
        # sha256(key) → {"org_id": str, "hint": str}.  No plaintext keys at rest.
        self._store: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._seed_from_env()

    def _seed_from_env(self) -> None:
        raw = os.environ.get("NETLOGIC_API_KEYS", "")
        for pair in raw.split(","):
            pair = pair.strip()
            if ":" in pair:
                key, org = pair.split(":", 1)
                key, org = key.strip(), org.strip()
                if key and org:
                    with self._lock:
                        self._store[self._hash(key)] = {"org_id": org, "hint": self._hint(key)}

    # ── Core operations ───────────────────────────────────────────────────────

    def lookup(self, key: str) -> Optional[str]:
        """Return the org_id for this API key, or None if unknown."""
        if not key:
            return None
        with self._lock:
            rec = self._store.get(self._hash(key))
            return rec["org_id"] if rec else None

    def create(self, org_id: str) -> str:
        """Generate a new API key for org_id.  Returns the plaintext key (once)."""
        key = uuid.uuid4().hex  # 32 hex chars — no hyphens
        with self._lock:
            self._store[self._hash(key)] = {"org_id": org_id, "hint": self._hint(key)}
        return key

    def revoke(self, key: str) -> bool:
        """Remove an API key.  Returns True if it existed."""
        with self._lock:
            h = self._hash(key)
            if h in self._store:
                del self._store[h]
                return True
            return False

    def list_keys(self) -> list[dict]:
        """Return all keys with the key masked (first 8 + '…') for safe display."""
        with self._lock:
            return [
                {"key_masked": rec["hint"] + "…", "org_id": rec["org_id"]}
                for rec in self._store.values()
            ]


class PgApiKeyStore:
    """Postgres-backed API key store (same interface as ApiKeyStore).

    Keys are hashed at rest (sha256) exactly like the in-memory store; only the
    hash and an 8-char prefix hint are persisted. `org_id` is the org SLUG (what
    require_org returns and jobs/agents are scoped by); the api_keys table refs
    organizations by uuid, so we join through the slug. Used only when
    NETLOGIC_DATABASE_URL is set; otherwise the in-memory store is selected.
    """

    @staticmethod
    def _hash(key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    @staticmethod
    def _hint(key: str) -> str:
        return key[:8]

    def lookup(self, key: str) -> Optional[str]:
        if not key:
            return None
        from api import db  # noqa: PLC0415
        h = self._hash(key)
        with db.connection() as conn:
            row = conn.execute(
                "SELECT o.slug FROM api_keys k JOIN organizations o ON o.id = k.org_id "
                "WHERE k.key_hash = %s AND k.revoked_at IS NULL "
                "AND (k.expires_at IS NULL OR k.expires_at > now())",
                (h,),
            ).fetchone()
            if not row:
                return None
            conn.execute("UPDATE api_keys SET last_used_at = now() WHERE key_hash = %s", (h,))
            return row[0]

    def create(self, org_id: str) -> str:
        key = uuid.uuid4().hex
        from api import db  # noqa: PLC0415
        with db.connection() as conn:
            conn.execute(
                "INSERT INTO organizations (slug, name) VALUES (%s, %s) "
                "ON CONFLICT (slug) DO NOTHING",
                (org_id, org_id),
            )
            org_uuid = conn.execute(
                "SELECT id FROM organizations WHERE slug = %s", (org_id,)
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO api_keys (org_id, key_hash, key_prefix) VALUES (%s, %s, %s)",
                (org_uuid, self._hash(key), self._hint(key)),
            )
        return key

    def revoke(self, key: str) -> bool:
        from api import db  # noqa: PLC0415
        with db.connection() as conn:
            cur = conn.execute(
                "UPDATE api_keys SET revoked_at = now() "
                "WHERE key_hash = %s AND revoked_at IS NULL",
                (self._hash(key),),
            )
            return cur.rowcount > 0

    def list_keys(self) -> list[dict]:
        from api import db  # noqa: PLC0415
        with db.connection() as conn:
            rows = conn.execute(
                "SELECT k.key_prefix, o.slug FROM api_keys k "
                "JOIN organizations o ON o.id = k.org_id WHERE k.revoked_at IS NULL"
            ).fetchall()
        return [{"key_masked": prefix + "…", "org_id": slug} for prefix, slug in rows]


# ── Helpers ───────────────────────────────────────────────────────────────────


def verify_admin(key: str) -> bool:
    """Constant-time check of the admin credential.

    Fails closed: if the configured ADMIN_KEY is missing or a known insecure
    placeholder, no key is ever accepted (prevents authenticating against an
    empty/default credential, including the empty-string-matches-empty-string
    pitfall of a naive compare_digest).
    """
    import hmac as _hmac
    if not ADMIN_KEY or ADMIN_KEY in INSECURE_ADMIN_KEYS:
        return False
    if not key:
        return False
    return _hmac.compare_digest(key, ADMIN_KEY)


# Process-wide singleton. Postgres-backed when NETLOGIC_DATABASE_URL is set,
# otherwise the in-memory store (local/desktop/tests). Selected once at import.
def _build_api_key_store():
    from api import db  # noqa: PLC0415
    return PgApiKeyStore() if db.is_enabled() else ApiKeyStore()


api_key_store = _build_api_key_store()
