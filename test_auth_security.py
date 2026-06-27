"""
Security regression tests for NetLogic authentication & licensing.

Scope: api/auth/{jwt_handler,api_keys,license,dependencies}.py

These tests are offline (no network, no real disk state beyond conftest's temp
dir) and set secrets via monkeypatched env + module reload, because JWT_SECRET
and ADMIN_KEY are resolved at import time.

Covered:
  • JWT valid round-trip
  • tampered signature / payload  → rejected
  • alg:none and non-HS256 (algorithm confusion) → rejected
  • expired / wrong-secret / missing / garbage → rejected
  • org isolation: org comes from the *verified token*, cross-org denied
  • require_org dependency 401 behaviour
  • license stub bounds (valid NL- / empty / short / non-prefixed)
  • constant-time compare used for admin key
"""
from __future__ import annotations

import base64
import importlib
import json
import time

import pytest
import sys

STRONG_SECRET = "s" * 48  # >= 32 chars, no weak patterns

# These tests reload the auth modules with patched secrets to exercise JWT/admin
# behavior. `monkeypatch` restores the ENV after each test, but a reloaded
# module's globals (JWT secret, admin key) persist in the shared pytest process
# and would desync OTHER test modules' app instances (e.g. test_production_
# readiness saw "Invalid admin key" 403s). Snapshot the auth module dicts up
# front and restore them when this module finishes so the suite stays isolated.
_AUTH_MODULES = (
    "api.auth.jwt_handler",
    "api.auth.api_keys",
    "api.auth.dependencies",
    "api.auth.license",
)


@pytest.fixture(autouse=True, scope="module")
def _restore_auth_module_state():
    for name in _AUTH_MODULES:
        importlib.import_module(name)
    snapshots = {name: dict(sys.modules[name].__dict__)
                 for name in _AUTH_MODULES if name in sys.modules}
    yield
    # Reverse any in-place reloads/mutations: restore each module's globals to
    # the pre-test snapshot so functions captured elsewhere read the original
    # secrets again.
    for name, snap in snapshots.items():
        mod = sys.modules.get(name)
        if mod is not None:
            mod.__dict__.clear()
            mod.__dict__.update(snap)


def _reload_jwt(monkeypatch, secret: str = STRONG_SECRET):
    monkeypatch.setenv("NETLOGIC_JWT_SECRET", secret)
    import api.auth.jwt_handler as j
    importlib.reload(j)
    return j


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


# ── JWT: valid round-trip ─────────────────────────────────────────────────────


def test_valid_roundtrip(monkeypatch):
    j = _reload_jwt(monkeypatch)
    tok = j.create_token(org_id="acme", sub="key-1")
    claims = j.verify_token(tok)
    assert claims is not None
    assert claims["org_id"] == "acme"
    assert claims["sub"] == "key-1"
    assert claims["exp"] > time.time()


# ── JWT: tampering ────────────────────────────────────────────────────────────


def test_tampered_payload_rejected(monkeypatch):
    j = _reload_jwt(monkeypatch)
    tok = j.create_token(org_id="acme", sub="k")
    h, p, s = tok.split(".")
    forged = json.loads(j._b64url_decode(p))
    forged["org_id"] = "evil-org"
    new_p = j._b64url_encode(json.dumps(forged).encode())
    assert j.verify_token(f"{h}.{new_p}.{s}") is None


def test_tampered_signature_rejected(monkeypatch):
    j = _reload_jwt(monkeypatch)
    tok = j.create_token(org_id="acme", sub="k")
    h, p, s = tok.split(".")
    # flip a character in the signature
    bad_sig = ("A" if s[0] != "A" else "B") + s[1:]
    assert j.verify_token(f"{h}.{p}.{bad_sig}") is None


# ── JWT: algorithm confusion ──────────────────────────────────────────────────


def test_alg_none_rejected(monkeypatch):
    j = _reload_jwt(monkeypatch)
    tok = j.create_token(org_id="acme", sub="k")
    _, p, _ = tok.split(".")
    none_hdr = _b64({"alg": "none", "typ": "JWT"})
    # empty signature, as a classic alg:none forgery would carry
    assert j.verify_token(f"{none_hdr}.{p}.") is None
    assert j.verify_token(f"{none_hdr}.{p}.{'x' * 10}") is None


def test_alg_uppercase_none_rejected(monkeypatch):
    j = _reload_jwt(monkeypatch)
    tok = j.create_token(org_id="acme", sub="k")
    _, p, _ = tok.split(".")
    for alg in ("None", "NONE", "nOnE"):
        hdr = _b64({"alg": alg, "typ": "JWT"})
        assert j.verify_token(f"{hdr}.{p}.") is None


def test_asymmetric_alg_confusion_rejected(monkeypatch):
    """A token claiming RS256/HS384/etc must be rejected even if HMAC-valid."""
    j = _reload_jwt(monkeypatch)
    for alg in ("RS256", "HS384", "HS512", "ES256", ""):
        hdr = _b64({"alg": alg, "typ": "JWT"})
        payload = _b64({"org_id": "acme", "sub": "k", "exp": int(time.time()) + 60})
        # Sign with the real HMAC secret so only the alg field is "wrong".
        sig = j._sign(hdr, payload)
        assert j.verify_token(f"{hdr}.{payload}.{sig}") is None


def test_missing_alg_rejected(monkeypatch):
    j = _reload_jwt(monkeypatch)
    hdr = _b64({"typ": "JWT"})
    payload = _b64({"org_id": "acme", "sub": "k", "exp": int(time.time()) + 60})
    sig = j._sign(hdr, payload)
    assert j.verify_token(f"{hdr}.{payload}.{sig}") is None


# ── JWT: expiry / wrong secret / malformed ────────────────────────────────────


def test_expired_rejected(monkeypatch):
    j = _reload_jwt(monkeypatch)
    tok = j.create_token(org_id="acme", sub="k", expiry_seconds=-1)
    assert j.verify_token(tok) is None


def test_no_exp_claim_rejected(monkeypatch):
    """A token with no exp must not be treated as never-expiring."""
    j = _reload_jwt(monkeypatch)
    hdr = j._HEADER_B64
    payload = _b64({"org_id": "acme", "sub": "k"})  # no exp
    sig = j._sign(hdr, payload)
    assert j.verify_token(f"{hdr}.{payload}.{sig}") is None


def test_wrong_secret_rejected(monkeypatch):
    j = _reload_jwt(monkeypatch, secret="a" * 40)
    tok = j.create_token(org_id="acme", sub="k")
    # Re-resolve the module under a *different* secret; the old token must fail.
    j2 = _reload_jwt(monkeypatch, secret="b" * 40)
    assert j2.verify_token(tok) is None


def test_garbage_and_missing_rejected(monkeypatch):
    j = _reload_jwt(monkeypatch)
    for bad in ("", "not.a.jwt", "only.two", "a.b.c.d", "....", "!!!.???.###"):
        assert j.verify_token(bad) is None


def test_ephemeral_secret_when_unset(monkeypatch):
    """Unset/placeholder secret must not crash import and must not be guessable."""
    j = _reload_jwt(monkeypatch, secret="changeme-in-production")
    # ephemeral random secret is generated; signing still works and is unforgeable
    tok = j.create_token(org_id="acme", sub="k")
    assert j.verify_token(tok)["org_id"] == "acme"
    # a token forged against the placeholder string must NOT verify
    hdr = j._HEADER_B64
    payload = _b64({"org_id": "acme", "sub": "k", "exp": int(time.time()) + 60})
    import hashlib
    import hmac as _h
    forged_sig = base64.urlsafe_b64encode(
        _h.new(b"changeme-in-production", f"{hdr}.{payload}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    assert j.verify_token(f"{hdr}.{payload}.{forged_sig}") is None


# ── Strong-secret enforcement ─────────────────────────────────────────────────


def test_require_strong_jwt_secret(monkeypatch):
    import api.auth.jwt_handler as j
    monkeypatch.setenv("NETLOGIC_JWT_SECRET", "changeme-in-production")
    with pytest.raises(RuntimeError):
        j.require_strong_jwt_secret()
    monkeypatch.setenv("NETLOGIC_JWT_SECRET", "short")
    with pytest.raises(RuntimeError):
        j.require_strong_jwt_secret()
    monkeypatch.setenv("NETLOGIC_JWT_SECRET", "password" + "x" * 30)
    with pytest.raises(RuntimeError):
        j.require_strong_jwt_secret()
    monkeypatch.setenv("NETLOGIC_JWT_SECRET", STRONG_SECRET)
    j.require_strong_jwt_secret()  # no raise


# ── Org isolation ─────────────────────────────────────────────────────────────


def test_org_comes_from_verified_token(monkeypatch):
    """org_id is derived from the verified claim, not anything client-controlled."""
    j = _reload_jwt(monkeypatch)
    import api.auth.dependencies as deps
    importlib.reload(deps)
    from fastapi.security import HTTPAuthorizationCredentials

    tok_a = j.create_token(org_id="org-a", sub="k")
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=tok_a)
    assert deps.require_org(creds) == "org-a"


def test_cross_org_token_not_reusable_as_other_org(monkeypatch):
    """Org A's token cannot be mutated into Org B without breaking the signature."""
    j = _reload_jwt(monkeypatch)
    import api.auth.dependencies as deps
    importlib.reload(deps)
    from fastapi import HTTPException
    from fastapi.security import HTTPAuthorizationCredentials

    tok_a = j.create_token(org_id="org-a", sub="k")
    h, p, s = tok_a.split(".")
    forged = json.loads(j._b64url_decode(p))
    forged["org_id"] = "org-b"
    new_p = j._b64url_encode(json.dumps(forged).encode())
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=f"{h}.{new_p}.{s}")
    with pytest.raises(HTTPException) as ei:
        deps.require_org(creds)
    assert ei.value.status_code == 401


def test_require_org_missing_header(monkeypatch):
    _reload_jwt(monkeypatch)
    import api.auth.dependencies as deps
    importlib.reload(deps)
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as ei:
        deps.require_org(None)
    assert ei.value.status_code == 401


def test_require_org_bad_token(monkeypatch):
    _reload_jwt(monkeypatch)
    import api.auth.dependencies as deps
    importlib.reload(deps)
    from fastapi import HTTPException
    from fastapi.security import HTTPAuthorizationCredentials

    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="garbage.token.here")
    with pytest.raises(HTTPException) as ei:
        deps.require_org(creds)
    assert ei.value.status_code == 401


def test_require_org_token_without_org_claim(monkeypatch):
    j = _reload_jwt(monkeypatch)
    import api.auth.dependencies as deps
    importlib.reload(deps)
    from fastapi import HTTPException
    from fastapi.security import HTTPAuthorizationCredentials

    hdr = j._HEADER_B64
    payload = _b64({"sub": "k", "exp": int(time.time()) + 60})  # no org_id
    sig = j._sign(hdr, payload)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=f"{hdr}.{payload}.{sig}")
    with pytest.raises(HTTPException) as ei:
        deps.require_org(creds)
    assert ei.value.status_code == 401


# ── Admin key: fail-closed + constant-time ────────────────────────────────────


def _reload_api_keys(monkeypatch, admin_key=None, api_keys=None):
    if admin_key is None:
        monkeypatch.delenv("NETLOGIC_ADMIN_KEY", raising=False)
    else:
        monkeypatch.setenv("NETLOGIC_ADMIN_KEY", admin_key)
    if api_keys is None:
        monkeypatch.delenv("NETLOGIC_API_KEYS", raising=False)
    else:
        monkeypatch.setenv("NETLOGIC_API_KEYS", api_keys)
    import api.auth.api_keys as ak
    importlib.reload(ak)
    return ak


def test_verify_admin_uses_constant_time(monkeypatch):
    """verify_admin must use hmac.compare_digest, not ==."""
    import inspect
    ak = _reload_api_keys(monkeypatch, admin_key="A" * 40)
    src = inspect.getsource(ak.verify_admin)
    assert "compare_digest" in src
    assert ak.verify_admin("A" * 40) is True
    assert ak.verify_admin("B" * 40) is False


def test_verify_admin_fails_closed_when_unset(monkeypatch):
    ak = _reload_api_keys(monkeypatch, admin_key=None)
    # No key configured: nothing authenticates, including the empty string.
    assert ak.verify_admin("") is False
    assert ak.verify_admin("anything") is False
    assert ak.verify_admin("admin-changeme") is False


def test_verify_admin_rejects_placeholder(monkeypatch):
    ak = _reload_api_keys(monkeypatch, admin_key="admin-changeme")
    assert ak.verify_admin("admin-changeme") is False


def test_require_strong_admin_key(monkeypatch):
    ak = _reload_api_keys(monkeypatch, admin_key="admin-changeme")
    with pytest.raises(RuntimeError):
        ak.require_strong_admin_key()
    ak = _reload_api_keys(monkeypatch, admin_key="short")
    with pytest.raises(RuntimeError):
        ak.require_strong_admin_key()
    ak = _reload_api_keys(monkeypatch, admin_key="Z" * 40)
    ak.require_strong_admin_key()  # no raise


# ── API key store + org mapping ───────────────────────────────────────────────


def test_api_key_store_seed_and_lookup(monkeypatch):
    ak = _reload_api_keys(monkeypatch, admin_key="Z" * 40, api_keys="k-aaa:org-a,k-bbb:org-b")
    assert ak.api_key_store.lookup("k-aaa") == "org-a"
    assert ak.api_key_store.lookup("k-bbb") == "org-b"
    assert ak.api_key_store.lookup("k-aaa ") is None  # no accidental fuzzy match
    assert ak.api_key_store.lookup("unknown") is None


def test_api_key_create_revoke(monkeypatch):
    ak = _reload_api_keys(monkeypatch, admin_key="Z" * 40)
    key = ak.api_key_store.create("org-x")
    assert ak.api_key_store.lookup(key) == "org-x"
    assert ak.api_key_store.revoke(key) is True
    assert ak.api_key_store.lookup(key) is None
    assert ak.api_key_store.revoke(key) is False


def test_api_key_list_masks_keys(monkeypatch):
    ak = _reload_api_keys(monkeypatch, admin_key="Z" * 40, api_keys="supersecretkey123:org-a")
    listed = ak.api_key_store.list_keys()
    assert listed
    for row in listed:
        assert "supersecretkey123" not in row["key_masked"]


# ── License stub bounds ───────────────────────────────────────────────────────


def test_license_valid_nl_prefix(monkeypatch):
    monkeypatch.delenv("NETLOGIC_VALID_LICENSES", raising=False)
    from api.auth.license import validate_license_key as v
    assert v("NL-1234567")["valid"] is True
    assert v("nl-1234567")["valid"] is True  # case-insensitive prefix
    assert v("  NL-abcdefghij  ")["valid"] is True  # trimmed


def test_license_rejects_invalid(monkeypatch):
    monkeypatch.delenv("NETLOGIC_VALID_LICENSES", raising=False)
    from api.auth.license import validate_license_key as v
    for bad in (None, "", "   ", "NL-", "NL-123", "XX-1234567890", "1234567890"):
        assert v(bad) is None


def test_license_env_allowlist(monkeypatch):
    monkeypatch.setenv("NETLOGIC_VALID_LICENSES", "EXPLICIT-KEY-1, EXPLICIT-KEY-2")
    from api.auth.license import validate_license_key as v
    assert v("EXPLICIT-KEY-1")["valid"] is True
    assert v("EXPLICIT-KEY-2")["valid"] is True
    assert v("EXPLICIT-KEY-3") is None  # not in allowlist, not NL- prefixed


# ── No secret leakage in error messages ───────────────────────────────────────


def test_jwt_errors_do_not_leak_secret(monkeypatch):
    secret = "TOPSECRET" + "z" * 40
    j = _reload_jwt(monkeypatch, secret=secret)
    # verify_token never raises and never returns the secret
    assert j.verify_token("garbage") is None
    assert secret not in repr(j.verify_token("a.b.c"))


def test_license_status_masks_key(monkeypatch, tmp_path):
    monkeypatch.delenv("NETLOGIC_VALID_LICENSES", raising=False)
    import api.auth.license as lic
    # Redirect the on-disk secrets file so activate() never touches real ~/.netlogic.
    monkeypatch.setattr(lic, "_SECRETS_FILE", tmp_path / "secrets.json")
    mgr = lic.LicenseManager()
    ok, _ = mgr.activate("NL-supersecretlicense123")
    assert ok is True
    status = mgr.status()
    assert "supersecretlicense123" not in str(status)
    assert status["licensed"] is True
