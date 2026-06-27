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

# Honor NETLOGIC_DATA_DIR (same convention as src/epss.py and the VDB cache) so
# state stays isolated under test/CI and relocatable in production. Unset in a
# normal install → defaults to ~/.netlogic, so production behavior is unchanged.
_DATA_DIR = Path(os.environ.get("NETLOGIC_DATA_DIR") or (Path.home() / ".netlogic"))
_SECRETS_FILE = _DATA_DIR / "secrets.json"
_KEY_FIELD = "NETLOGIC_LICENSE_KEY"


def _load_key() -> str:
    try:
        data = json.loads(_SECRETS_FILE.read_text())
        return data.get(_KEY_FIELD, os.environ.get("NETLOGIC_LICENSE_KEY", ""))
    except Exception:
        return os.environ.get("NETLOGIC_LICENSE_KEY", "")


def _save_key(key: str) -> None:
    import os as _os, tempfile as _tempfile  # noqa: PLC0415
    _SECRETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    data: dict = {}
    if _SECRETS_FILE.exists():
        try:
            data = json.loads(_SECRETS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    data[_KEY_FIELD] = key
    # Atomic tmp+replace so a crash mid-write never corrupts the real file.
    fd, tmp = _tempfile.mkstemp(dir=str(_SECRETS_FILE.parent))
    try:
        with _os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, indent=2))
            fh.flush()
            _os.fsync(fh.fileno())
        _os.replace(tmp, str(_SECRETS_FILE))
    except Exception:
        # Clean up the temp file on failure; propagate the error to the caller.
        try:
            _os.unlink(tmp)
        except OSError:
            pass
        raise


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

    def activate(self, key: str) -> tuple[bool, str]:
        """Validate and persist a license key. Returns (ok, msg)."""
        result = validate_license_key(key)
        if result:
            self._key = key.strip()
            self._valid = True
            self._plan = result.get("plan")
            self._licensed_at = time.time()
            try:
                _save_key(self._key)
            except OSError:
                return True, "License activated (in-memory only; disk write failed)."
            return True, "License activated."
        return False, "Invalid license key."

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
