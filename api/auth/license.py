"""
License management — stub validator ready for real payment integration.

To integrate Stripe / Paddle / Lemon Squeezy:
    Replace the body of validate_license_key() with an HTTP call to your
    licensing server.  Everything else (LicenseManager, middleware, CLI check)
    stays the same.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

_SECRETS_FILE = Path.home() / ".netlogic" / "secrets.json"
_KEY_FIELD = "NETLOGIC_LICENSE_KEY"


def _load_key() -> str:
    try:
        data = json.loads(_SECRETS_FILE.read_text())
        return data.get(_KEY_FIELD, os.environ.get("NETLOGIC_LICENSE_KEY", ""))
    except Exception:
        return os.environ.get("NETLOGIC_LICENSE_KEY", "")


def _save_key(key: str) -> None:
    try:
        data: dict = {}
        if _SECRETS_FILE.exists():
            try:
                data = json.loads(_SECRETS_FILE.read_text())
            except Exception:
                pass
        data[_KEY_FIELD] = key
        _SECRETS_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SECRETS_FILE.write_text(json.dumps(data, indent=2))
    except Exception:
        pass


def validate_license_key(key: str) -> Optional[dict]:
    """
    Returns a plan dict if the key is valid, None if invalid.

    Stub implementation — replace with a real licensing API call:

        import httpx
        r = httpx.post(
            "https://api.netlogic.io/v1/licenses/validate",
            json={"key": key},
            timeout=5,
        )
        return r.json() if r.status_code == 200 else None
    """
    if not key or not key.strip():
        return None
    key = key.strip()

    # Allow specific keys set in the environment (comma-separated) — for CI / dev.
    valid_env = os.environ.get("NETLOGIC_VALID_LICENSES", "")
    if valid_env:
        if key in [k.strip() for k in valid_env.split(",") if k.strip()]:
            return {"plan": "pro", "valid": True}

    # Stub: keys starting with NL- (at least 10 chars) are treated as valid.
    # Replace this with a real check before shipping to production.
    if key.upper().startswith("NL-") and len(key) >= 10:
        return {"plan": "pro", "valid": True}

    return None


class LicenseManager:
    """Process-wide singleton that tracks license state."""

    def __init__(self) -> None:
        self._key: str = _load_key()
        self._plan: Optional[str] = None
        self._valid: bool = False
        self._licensed_at: Optional[float] = None
        if self._key:
            result = validate_license_key(self._key)
            if result:
                self._valid = True
                self._plan = result.get("plan")
                self._licensed_at = time.time()

    def activate(self, key: str) -> bool:
        """Validate and persist a license key. Returns True on success."""
        result = validate_license_key(key)
        if result:
            self._key = key.strip()
            self._valid = True
            self._plan = result.get("plan")
            self._licensed_at = time.time()
            _save_key(self._key)
            return True
        return False

    @property
    def is_licensed(self) -> bool:
        return self._valid

    def status(self) -> dict:
        hint = None
        if self._key and len(self._key) > 8:
            hint = self._key[:4] + "…" + self._key[-4:]
        return {
            "licensed": self._valid,
            "plan": self._plan,
            "key_hint": hint,
        }


license_manager = LicenseManager()
