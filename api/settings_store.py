"""
NetLogic — per-org AI / fusion provider settings store.

Each organisation owns its LLM credentials (provider, key, model, base_url) for
two roles: 'ai' (the report writer) and 'fusion' (the gray-band adjudicator).
The API key is sealed at rest via api.crypto; only a masked hint is ever
returned for display.

This is the fix for cross-tenant key leakage: previously every scan read one
process-global key (os.environ / secrets.json), so org B's scan used whatever
key org A saved last. Now keys are keyed by org_id and resolved per job.

Two backends, selected once at import by db.is_enabled() — identical to
api.auth.api_keys.api_key_store:
  • OrgSettingsStore    — in-process dict (desktop / dev / tests).
  • PgOrgSettingsStore  — org_ai_settings table (multi-tenant production).

Record shape returned by get():
  {"provider": str, "model": str|None, "base_url": str|None,
   "api_key": str|None,        # DECRYPTED — callers use it transiently then drop
   "key_hint": str}            # masked, safe to display
"""
from __future__ import annotations

import json
import os
import threading
from typing import Optional

from api import crypto

ROLES = ("ai", "fusion")


def _mask(key: str) -> str:
    if not key:
        return ""
    return (key[:4] + "…" + key[-4:]) if len(key) > 12 else "set"


_safe_open_warned: set[bytes] = set()


def _safe_open(ct) -> Optional[str]:
    """Decrypt a stored key, degrading to None (treated as "no key set") if it
    can't be decrypted. A key sealed under a different/ephemeral NETLOGIC_SECRETS_KEY
    becomes undecryptable after a key change or restart; that must not 500 the whole
    settings endpoint — the user simply re-enters the key. Returns None for empty ct.

    Warns at most ONCE per ciphertext so repeated settings access doesn't spam logs.
    """
    if not ct:
        return None
    try:
        return crypto.open_secret(ct) or None
    except Exception:
        if ct not in _safe_open_warned:
            _safe_open_warned.add(ct)
            import logging  # noqa: PLC0415
            logging.getLogger("netlogic.settings").warning(
                "stored AI key could not be decrypted (NETLOGIC_SECRETS_KEY changed or "
                "ephemeral); treating as unset — re-enter the key to fix."
            )
        return None


def _normalize(role: str) -> str:
    role = (role or "ai").strip().lower()
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}, got {role!r}")
    return role


SETTINGS_FILE: str = os.path.join(
    os.environ.get("NETLOGIC_SCANS_DIR", os.path.join(os.path.expanduser("~"), ".netlogic")),
    "org_settings.json",
)


class OrgSettingsStore:
    """Per-org settings backed by a JSON file so they survive restarts."""

    def __init__(self) -> None:
        # (org_id, role) → {"provider","model","base_url","key_ct" (bytes|None),"key_hint"}
        self._store: dict[tuple[str, str], dict] = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self) -> None:
        try:
            with open(SETTINGS_FILE) as f:
                raw = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return
        for entry in raw:
            org_id = entry.get("org_id")
            role = entry.get("role")
            rec = {
                "provider": entry["provider"],
                "model": entry.get("model"),
                "base_url": entry.get("base_url"),
                "key_hint": entry.get("key_hint", ""),
            }
            ct_hex = entry.get("key_ct_hex")
            rec["key_ct"] = bytes.fromhex(ct_hex) if ct_hex else None
            if org_id and role:
                self._store[(org_id, _normalize(role))] = rec

    def _save(self) -> None:
        rows = []
        for (org_id, role), rec in self._store.items():
            ct = rec.get("key_ct")
            rows.append({
                "org_id": org_id,
                "role": role,
                "provider": rec.get("provider", "openrouter"),
                "model": rec.get("model"),
                "base_url": rec.get("base_url"),
                "key_ct_hex": ct.hex() if ct else None,
                "key_hint": rec.get("key_hint", ""),
            })
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w") as f:
            json.dump(rows, f, indent=2)

    def put(self, org_id: str, role: str, *, provider: str,
            model: Optional[str] = None, base_url: Optional[str] = None,
            api_key: Optional[str] = None, keep_key: bool = True) -> None:
        """Upsert a role's config for an org.

        api_key semantics: None + keep_key=True → keep existing; ""/None +
        keep_key=False → clear the key; a non-empty string → set (and seal) it.
        """
        role = _normalize(role)
        with self._lock:
            rec = dict(self._store.get((org_id, role)) or {})
            rec["provider"] = provider
            if model is not None:
                rec["model"] = model or None
            if base_url is not None:
                rec["base_url"] = base_url or None
            if api_key:
                rec["key_ct"] = crypto.seal(api_key)
                rec["key_hint"] = _mask(api_key)
            elif provider == "ollama":
                rec["key_ct"] = None
                rec["key_hint"] = ""
            elif not keep_key:
                rec["key_ct"] = None
                rec["key_hint"] = ""
            self._store[(org_id, role)] = rec
            self._save()

    def get(self, org_id: str, role: str) -> Optional[dict]:
        role = _normalize(role)
        with self._lock:
            rec = self._store.get((org_id, role))
            if rec is None:
                return None
            ct = rec.get("key_ct")
            return {
                "provider": rec.get("provider") or "openrouter",
                "model": rec.get("model"),
                "base_url": rec.get("base_url"),
                "api_key": _safe_open(ct),
                "key_hint": rec.get("key_hint") or "",
            }


class PgOrgSettingsStore:
    """Postgres-backed per-org settings (org_ai_settings). Same interface."""

    def put(self, org_id: str, role: str, *, provider: str,
            model: Optional[str] = None, base_url: Optional[str] = None,
            api_key: Optional[str] = None, keep_key: bool = True) -> None:
        role = _normalize(role)
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

            if api_key:
                ct, hint = crypto.seal(api_key), _mask(api_key)
                conn.execute(
                    "INSERT INTO org_ai_settings (org_id, role, provider, model, base_url, key_ciphertext, key_hint) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT (org_id, role) DO UPDATE SET "
                    "provider=EXCLUDED.provider, model=EXCLUDED.model, base_url=EXCLUDED.base_url, "
                    "key_ciphertext=EXCLUDED.key_ciphertext, key_hint=EXCLUDED.key_hint, updated_at=now()",
                    (org_uuid, role, provider, model or None, base_url or None, ct, hint),
                )
            elif not keep_key:
                conn.execute(
                    "INSERT INTO org_ai_settings (org_id, role, provider, model, base_url, key_ciphertext, key_hint) "
                    "VALUES (%s,%s,%s,%s,%s,NULL,'') "
                    "ON CONFLICT (org_id, role) DO UPDATE SET "
                    "provider=EXCLUDED.provider, model=EXCLUDED.model, base_url=EXCLUDED.base_url, "
                    "key_ciphertext=NULL, key_hint='', updated_at=now()",
                    (org_uuid, role, provider, model or None, base_url or None),
                )
            else:
                # Keep the existing key; update only the non-secret fields.
                conn.execute(
                    "INSERT INTO org_ai_settings (org_id, role, provider, model, base_url) "
                    "VALUES (%s,%s,%s,%s,%s) "
                    "ON CONFLICT (org_id, role) DO UPDATE SET "
                    "provider=EXCLUDED.provider, model=EXCLUDED.model, base_url=EXCLUDED.base_url, updated_at=now()",
                    (org_uuid, role, provider, model or None, base_url or None),
                )

    def get(self, org_id: str, role: str) -> Optional[dict]:
        role = _normalize(role)
        from api import db  # noqa: PLC0415
        with db.connection() as conn:
            row = conn.execute(
                "SELECT s.provider, s.model, s.base_url, s.key_ciphertext, s.key_hint "
                "FROM org_ai_settings s JOIN organizations o ON o.id = s.org_id "
                "WHERE o.slug = %s AND s.role = %s",
                (org_id, role),
            ).fetchone()
        if not row:
            return None
        provider, model, base_url, ct, hint = row
        return {
            "provider": provider or "openrouter",
            "model": model,
            "base_url": base_url,
            "api_key": _safe_open(ct),
            "key_hint": hint or "",
        }


def _build_store():
    from api import db  # noqa: PLC0415
    return PgOrgSettingsStore() if db.is_enabled() else OrgSettingsStore()


org_settings_store = _build_store()
