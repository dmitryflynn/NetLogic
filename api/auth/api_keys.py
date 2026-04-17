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

import os
import uuid
from typing import Optional

ADMIN_KEY: str = os.environ.get("NETLOGIC_ADMIN_KEY", "admin-changeme")


class ApiKeyStore:
    """In-memory mapping of API key → org_id."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}  # key → org_id
        self._seed_from_env()

    def _seed_from_env(self) -> None:
        raw = os.environ.get("NETLOGIC_API_KEYS", "")
        for pair in raw.split(","):
            pair = pair.strip()
            if ":" in pair:
                key, org = pair.split(":", 1)
                key, org = key.strip(), org.strip()
                if key and org:
                    self._store[key] = org

    # ── Core operations ───────────────────────────────────────────────────────

    def lookup(self, key: str) -> Optional[str]:
        """Return the org_id for this API key, or None if unknown."""
        return self._store.get(key)

    def create(self, org_id: str) -> str:
        """Generate a new API key for org_id.  Returns the plaintext key."""
        key = uuid.uuid4().hex  # 32 hex chars — no hyphens
        self._store[key] = org_id
        return key

    def revoke(self, key: str) -> bool:
        """Remove an API key.  Returns True if it existed."""
        if key in self._store:
            del self._store[key]
            return True
        return False

    def list_keys(self) -> list[dict]:
        """Return all keys with the key masked (first 8 + '…') for safe display."""
        return [
            {"key_masked": k[:8] + "…", "org_id": org}
            for k, org in self._store.items()
        ]


# ── Helpers ───────────────────────────────────────────────────────────────────


def verify_admin(key: str) -> bool:
    """Constant-time check of the admin credential."""
    import hmac as _hmac
    return _hmac.compare_digest(key, ADMIN_KEY)


# Process-wide singleton.
api_key_store = ApiKeyStore()
