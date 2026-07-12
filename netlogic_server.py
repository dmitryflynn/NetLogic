#!/usr/bin/env python3
"""Headless NetLogic API server for Electron / desktop packaging.

Prints one readiness line Electron parses:

    NETLOGIC_SERVER {"url":"http://127.0.0.1:8000","api_key":"...","port":8000}

Then runs uvicorn on api.main:app (same stack as `python netlogic.py --gui`).
"""
from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
os.chdir(_ROOT)


def _ensure_secrets() -> str:
    config_dir = Path.home() / ".netlogic"
    secrets_file = config_dir / "secrets.json"
    data: dict = {}
    if secrets_file.exists():
        try:
            data = json.loads(secrets_file.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    changed = False
    for key in ("NETLOGIC_JWT_SECRET", "NETLOGIC_ADMIN_KEY", "NETLOGIC_API_KEY"):
        if not data.get(key):
            data[key] = (
                secrets.token_urlsafe(32)
                if key == "NETLOGIC_ADMIN_KEY"
                else secrets.token_hex(32)
            )
            changed = True
    if changed:
        config_dir.mkdir(parents=True, exist_ok=True)
        secrets_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        try:
            secrets_file.chmod(0o600)
        except Exception:
            pass
    for k, v in data.items():
        os.environ.setdefault(str(k), str(v))
    api_key = str(data["NETLOGIC_API_KEY"])
    os.environ["NETLOGIC_API_KEYS"] = f"{api_key}:default"
    os.environ.setdefault("NETLOGIC_VALID_LICENSES", "NL-LOCAL-DESKTOP")
    os.environ.setdefault("NETLOGIC_LICENSE_KEY", "NL-LOCAL-DESKTOP")
    os.environ["NETLOGIC_NO_BROWSER"] = "1"
    return api_key


def main() -> None:
    api_key = _ensure_secrets()
    port = int(os.environ.get("NETLOGIC_PORT", "8000"))
    host = os.environ.get("NETLOGIC_HOST", "127.0.0.1")
    url = f"http://127.0.0.1:{port}"
    # Electron readiness marker (must be a single line after the prefix).
    print(
        "NETLOGIC_SERVER "
        + json.dumps({"url": url, "api_key": api_key, "port": port}, separators=(",", ":")),
        flush=True,
    )
    import uvicorn  # noqa: PLC0415

    uvicorn.run("api.main:app", host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
