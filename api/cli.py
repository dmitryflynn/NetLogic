"""
netlogic — one-command launcher for the NetLogic web dashboard.

Usage:
    pip install -e .
    netlogic
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

CONFIG_DIR   = Path.home() / ".netlogic"
SECRETS_FILE = CONFIG_DIR / "secrets.json"
PROJECT_ROOT = Path(__file__).parent.parent
DIST_DIR     = PROJECT_ROOT / "dashboard" / "dist"


def _load_or_generate_secrets() -> dict:
    """Load secrets from ~/.netlogic/secrets.json, generating them on first run."""
    if SECRETS_FILE.exists():
        try:
            data = json.loads(SECRETS_FILE.read_text())
        except Exception:
            data = {}
    else:
        data = {}

    changed = False
    if not data.get("NETLOGIC_JWT_SECRET"):
        data["NETLOGIC_JWT_SECRET"] = secrets.token_hex(32)
        changed = True
    if not data.get("NETLOGIC_ADMIN_KEY"):
        data["NETLOGIC_ADMIN_KEY"] = secrets.token_urlsafe(32)
        changed = True
    if not data.get("NETLOGIC_API_KEY"):
        data["NETLOGIC_API_KEY"] = secrets.token_hex(32)
        changed = True

    if changed:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        SECRETS_FILE.write_text(json.dumps(data, indent=2))
        try:
            SECRETS_FILE.chmod(0o600)
        except Exception:
            pass

    for k, v in data.items():
        os.environ.setdefault(k, v)

    return data


def _ensure_dashboard_built() -> None:
    """Build the React dashboard on first run if dist/ doesn't exist."""
    if (DIST_DIR / "index.html").exists():
        return

    dashboard_dir = PROJECT_ROOT / "dashboard"
    if not dashboard_dir.exists():
        print("[netlogic] Warning: dashboard/ not found — UI unavailable.")
        return

    print("[netlogic] Building dashboard for the first time (~30 s)...")
    try:
        subprocess.run("npm install", cwd=dashboard_dir, shell=True, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run("npm run build", cwd=dashboard_dir, shell=True, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[netlogic] Dashboard ready.")
    except subprocess.CalledProcessError:
        print("[netlogic] Warning: dashboard build failed — API-only mode.")
    except FileNotFoundError:
        print("[netlogic] Warning: npm not found — install Node.js to enable the dashboard.")


def _check_license() -> bool:
    """Verify a license key exists; prompt the user to enter one if not. Returns True if licensed."""
    from api.auth.license import license_manager  # noqa: PLC0415
    if license_manager.is_licensed:
        return True
    print()
    print("  No license key found.")
    print("  Get a license at: https://netlogic.io/pricing")
    print()
    try:
        key = input("  Enter license key (or press Enter to exit): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not key:
        return False
    if license_manager.activate(key):
        print("  License activated!")
        return True
    print("  Invalid license key. Visit https://netlogic.io/pricing to purchase.")
    return False


def main() -> None:
    data = _load_or_generate_secrets()

    # Inject the default API key so ApiKeyStore seeds it on import.
    api_key = data["NETLOGIC_API_KEY"]
    os.environ["NETLOGIC_API_KEYS"] = f"{api_key}:default"

    if not _check_license():
        sys.exit(1)

    _ensure_dashboard_built()

    port = int(os.environ.get("NETLOGIC_PORT", "8000"))
    host = os.environ.get("NETLOGIC_HOST", "0.0.0.0")
    url  = f"http://localhost:{port}"

    os.environ["NETLOGIC_NO_BROWSER"] = "1"

    print()
    print("  ███╗   ██╗███████╗████████╗██╗      ██████╗  ██████╗ ██╗ ██████╗")
    print("  ████╗  ██║██╔════╝╚══██╔══╝██║     ██╔═══██╗██╔════╝ ██║██╔════╝")
    print("  ██╔██╗ ██║█████╗     ██║   ██║     ██║   ██║██║  ███╗██║██║")
    print("  ██║╚██╗██║██╔══╝     ██║   ██║     ██║   ██║██║   ██║██║██║")
    print("  ██║ ╚████║███████╗   ██║   ███████╗╚██████╔╝╚██████╔╝██║╚██████╗")
    print("  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝ ╚═════╝")
    print()
    print(f"  URL:     {url}")
    print(f"  API Key: {api_key}")
    print()
    print("  Paste the API Key into the login screen.")
    print("  Press Ctrl+C to stop.")
    print()

    threading.Timer(1.5, webbrowser.open, args=(url,)).start()

    # Auto-start a local scan agent after the server has had time to bind.
    agent_script = PROJECT_ROOT / "netlogic_agent.py"
    if agent_script.exists():
        def _start_local_agent():
            import time as _t
            _t.sleep(2.5)  # wait for uvicorn to be ready
            subprocess.Popen(
                [sys.executable, str(agent_script),
                 "--controller", url,
                 "--api-key", api_key,
                 "--hostname", "localhost"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        threading.Thread(target=_start_local_agent, daemon=True).start()

    import uvicorn  # noqa: PLC0415
    uvicorn.run("api.main:app", host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
