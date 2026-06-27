"""
NetLogic — secret sealing for credentials stored at rest.

Per-org LLM API keys must never sit in the database (or the in-memory fallback)
as plaintext: a DB dump, replica, or backup would then leak every tenant's
provider credentials. We seal them with Fernet (AES-128-CBC + HMAC-SHA256,
authenticated) using a single master key from the environment.

    NETLOGIC_SECRETS_KEY    a urlsafe-base64 32-byte Fernet key. Generate with:
                            python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Design choices
──────────────
• Fail-CLOSED in production: if a Postgres deployment has no master key, seal()
  raises rather than silently storing plaintext. A missing key is an operator
  error, not a reason to weaken the security boundary.
• Local/dev/desktop tolerance: when Postgres is NOT enabled (single-tenant
  desktop / tests), an absent master key is tolerated and we auto-create a durable
  per-install key, persisted to a local file (0600) on first run, so a user can get
  started without setting NETLOGIC_SECRETS_KEY and saved API keys survive restarts.
  Override the file location with NETLOGIC_SECRETS_DIR.
• cryptography is already a dependency (RSA verification in api/auth/oidc.py), so
  this adds no new install surface; it is imported lazily all the same.
"""
from __future__ import annotations

import os
import threading

_lock = threading.Lock()
_fernet = None          # cached cryptography.fernet.Fernet
_ephemeral = False      # True when using a process-local key (no master configured)


class SecretsKeyError(RuntimeError):
    """Raised when sealing is required but no master key is configured."""


def _master_key_present() -> bool:
    return bool((os.environ.get("NETLOGIC_SECRETS_KEY") or "").strip())


def _build_fernet():
    """Return a Fernet, building it once. Chooses the master key, or — only when
    Postgres is disabled — an ephemeral per-process key so dev/tests round-trip."""
    global _fernet, _ephemeral
    if _fernet is not None:
        return _fernet
    with _lock:
        if _fernet is not None:
            return _fernet
        from cryptography.fernet import Fernet  # noqa: PLC0415 — lazy
        raw = (os.environ.get("NETLOGIC_SECRETS_KEY") or "").strip()
        if raw:
            try:
                _fernet = Fernet(raw.encode("utf-8"))
            except Exception as exc:  # malformed key — surface clearly, don't fall back
                raise SecretsKeyError(
                    "NETLOGIC_SECRETS_KEY is not a valid Fernet key. Generate one with: "
                    'python -c "from cryptography.fernet import Fernet; '
                    'print(Fernet.generate_key().decode())"'
                ) from exc
            _ephemeral = False
            return _fernet
        # No master key configured.
        from api import db  # noqa: PLC0415
        if db.is_enabled():
            # Production (durable storage) MUST have a real key — fail closed.
            raise SecretsKeyError(
                "NETLOGIC_SECRETS_KEY must be set when NETLOGIC_DATABASE_URL is configured, "
                "so per-org API keys are encrypted at rest. Generate one with: "
                'python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            )
        # Desktop/dev/tests with only the in-memory store: a durable per-install key,
        # auto-created on first run and persisted locally so the user gets started
        # without setting NETLOGIC_SECRETS_KEY and saved keys survive restarts.
        _fernet = _load_or_create_local_key()
        _ephemeral = False
        return _fernet


def _local_key_path() -> str:
    base = (os.environ.get("NETLOGIC_SECRETS_DIR")
            or os.environ.get("NETLOGIC_SCANS_DIR")
            or os.path.join(os.path.expanduser("~"), ".netlogic"))
    return os.path.join(base, "secrets.key")


def _load_or_create_local_key():
    """Desktop/dev only: a durable per-install Fernet key. Reused from a local file if
    present, otherwise generated and written (0600) on first run. NOT reached when
    Postgres is enabled — multi-tenant deploys must set NETLOGIC_SECRETS_KEY (the
    fail-closed branch above)."""
    from cryptography.fernet import Fernet  # noqa: PLC0415 — lazy
    path = _local_key_path()
    try:
        with open(path, "rb") as fh:
            raw = fh.read().strip()
        if raw:
            return Fernet(raw)
    except FileNotFoundError:
        pass
    except Exception:
        # Unreadable/corrupt key file: regenerate rather than hard-fail. Any key
        # sealed under the old value degrades to "unset" (see settings_store._safe_open).
        pass
    raw = Fernet.generate_key()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(raw)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best-effort; Windows ACLs differ
    return Fernet(raw)


def seal(plaintext: str) -> bytes:
    """Encrypt a secret for storage. Raises SecretsKeyError if a key is required
    but absent (fail-closed in production)."""
    if plaintext is None:
        raise ValueError("seal() requires a non-None plaintext")
    return _build_fernet().encrypt(plaintext.encode("utf-8"))


def open_secret(ciphertext: bytes) -> str:
    """Decrypt a sealed secret. Returns "" for falsy input (no key stored)."""
    if not ciphertext:
        return ""
    if isinstance(ciphertext, memoryview):
        ciphertext = ciphertext.tobytes()
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode("utf-8")
    return _build_fernet().decrypt(ciphertext).decode("utf-8")


def require_secrets_key() -> None:
    """Enforce a real master key at startup (call when prod + Postgres are on).

    Mirrors require_strong_admin_key / require_strong_jwt_secret: fail fast with a
    clear RuntimeError instead of letting a multi-tenant deploy run until the first
    per-org key save returns 503. Validates the key actually parses, too."""
    if not _master_key_present():
        raise SecretsKeyError(
            "NETLOGIC_SECRETS_KEY must be set in production with a database configured, "
            "so per-org API keys are encrypted at rest. Generate one with: "
            'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
        )
    _build_fernet()  # raises SecretsKeyError if the key is malformed


def is_ephemeral() -> bool:
    """True when sealing uses a throwaway per-process key (no master configured).
    Such ciphertext cannot be decrypted after restart — only valid for the
    in-memory store, never for persisted rows."""
    _build_fernet()
    return _ephemeral


def reset_for_tests() -> None:
    """Drop the cached Fernet so a test can change NETLOGIC_SECRETS_KEY."""
    global _fernet, _ephemeral
    with _lock:
        _fernet = None
        _ephemeral = False
