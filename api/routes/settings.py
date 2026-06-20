"""
NetLogic API — operator settings (AI configuration).

Lets an operator configure the LLM provider / API key / model from the dashboard
instead of only via environment variables. Persisted to secrets.json — the same
file the server loads into the environment on startup (api/cli._load_or_generate_
secrets) — and applied to os.environ live, so the next scan's AI analysis uses it
without a restart.

Security: the API key is WRITE-ONLY. GET never returns it, only whether one is
set plus a short masked hint. All endpoints require a valid JWT (org scope).
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.auth.dependencies import require_org
from api.auth.rate_limit import settings_limiter
from api.middleware.audit import audit_log
from src.ai_analyst import ALLOWED_PROVIDERS, PROVIDER_PRESETS, config_from_env

router = APIRouter(prefix="/settings", tags=["settings"])

# Persist alongside the other secrets the server loads at startup. Honors
# NETLOGIC_DATA_DIR (test isolation); defaults to ~/.netlogic in production —
# the same path api/cli writes, so the value is picked up on the next startup.
_DATA_DIR = Path(os.environ.get("NETLOGIC_DATA_DIR") or (Path.home() / ".netlogic"))
_SECRETS_FILE = _DATA_DIR / "secrets.json"

# Per-role env-var field names. "ai" = the AI-analyst report; "fusion" = the fusion
# adjudicator (may use a different provider/model/key).
_ROLE_FIELDS = {
    "ai": {
        "provider": "NETLOGIC_AI_PROVIDER", "key": "NETLOGIC_AI_API_KEY",
        "model": "NETLOGIC_AI_MODEL", "base_url": "NETLOGIC_AI_BASE_URL",
    },
    "fusion": {
        "provider": "NETLOGIC_FUSION_PROVIDER", "key": "NETLOGIC_FUSION_API_KEY",
        "model": "NETLOGIC_FUSION_MODEL", "base_url": "NETLOGIC_FUSION_BASE_URL",
    },
}

# Prevent TOCTOU races between concurrent _read_secrets / _write_secrets calls.
_settings_lock = threading.Lock()


def _read_secrets() -> dict:
    try:
        return json.loads(_SECRETS_FILE.read_text())
    except Exception:
        return {}


def _write_secrets(data: dict) -> None:
    """Atomically persist secrets.json (tmp + replace), owner-only perms."""
    _SECRETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _SECRETS_FILE.with_name(_SECRETS_FILE.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, _SECRETS_FILE)
    try:
        os.chmod(_SECRETS_FILE, 0o600)
    except OSError:
        # Windows: chmod only sets the read-only flag, not Unix-style owner-only
        # permissions. The file is still protected by the OS user account boundary.
        import logging  # noqa: PLC0415
        logging.getLogger("netlogic.settings").warning(
            "Could not set owner-only permissions on %s (expected on Windows)", _SECRETS_FILE
        )


def _mask(key: str) -> str:
    if not key:
        return ""
    return (key[:4] + "…" + key[-4:]) if len(key) > 12 else "set"


def _config_for(role: str):
    from src.ai_analyst import config_from_env, fusion_config_from_env, fusion_has_separate_config  # noqa: PLC0415
    if role == "fusion":
        return fusion_config_from_env().resolve(), (not fusion_has_separate_config())
    return config_from_env().resolve(), False


def _status(role: str = "ai") -> dict:
    """Current config for a role as the scanner sees it (key never exposed)."""
    cfg, inherits_ai = _config_for(role)
    return {
        "role": role,
        "provider": cfg.provider,
        "model": cfg.model or "",
        "base_url": cfg.base_url or "",
        "key_set": bool(cfg.api_key),
        "key_hint": _mask(cfg.api_key or ""),
        "inherits_ai": inherits_ai,            # fusion only: using the AI config (no separate key)
        "providers": sorted(ALLOWED_PROVIDERS),
        "presets": {p: {"base_url": v[0], "model": v[1]} for p, v in PROVIDER_PRESETS.items()},
    }


class AISettingsIn(BaseModel):
    provider: str = Field(..., max_length=32, description="openrouter|openai|anthropic|kimi|qwen|groq|ollama|custom")
    # Omit or leave empty to KEEP the existing stored key (write-only field).
    api_key: Optional[str] = Field(None, max_length=512)
    model: Optional[str] = Field(None, max_length=128)
    base_url: Optional[str] = Field(None, max_length=256)


def _apply_settings(role: str, payload: "AISettingsIn", request: Request, org_id: str) -> dict:
    if not settings_limiter.allow(org_id):
        raise HTTPException(status_code=429, detail="Too many settings updates. Slow down.")

    f = _ROLE_FIELDS[role]
    provider = (payload.provider or "").strip().lower()
    if provider not in ALLOWED_PROVIDERS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported provider '{provider}'. Use one of: {', '.join(sorted(ALLOWED_PROVIDERS))}.",
        )

    with _settings_lock:
        data = _read_secrets()
        data[f["provider"]] = provider
        if payload.model is not None:
            data[f["model"]] = payload.model.strip()
        if payload.base_url is not None:
            data[f["base_url"]] = payload.base_url.strip()
        # api_key: None=keep, ""=delete, "sk-..."=set.
        if payload.api_key is not None:
            stripped = payload.api_key.strip()
            if stripped:
                data[f["key"]] = stripped
            else:
                data.pop(f["key"], None)

        if provider == "custom" and not data.get(f["base_url"]):
            raise HTTPException(status_code=422, detail="The 'custom' provider requires a base_url.")

        _write_secrets(data)

    # Apply live so the next scan picks it up without a restart.
    os.environ[f["provider"]] = data.get(f["provider"], "")
    os.environ[f["model"]] = data.get(f["model"], "")
    os.environ[f["base_url"]] = data.get(f["base_url"], "")
    if f["key"] in data:
        os.environ[f["key"]] = data[f["key"]]
    else:
        os.environ.pop(f["key"], None)

    audit_log(f"{role}_settings_updated", org_id=org_id, provider=provider,
              ip=request.client.host if request.client else "")
    return _status(role)


def _run_test(role: str, org_id: str) -> dict:
    if not settings_limiter.allow(org_id):
        raise HTTPException(status_code=429, detail="Too many test requests. Slow down.")
    from src.ai_analyst import analyze  # noqa: PLC0415
    cfg, _ = _config_for(role)
    usable, reason = cfg.is_usable()
    if not usable:
        return {"ok": False, "error": reason}
    result = analyze({"_connectivity_test": "Reply with the single word: OK."}, cfg)
    if result.error:
        return {"ok": False, "error": result.error, "provider": cfg.provider, "model": cfg.model}
    return {"ok": True, "provider": cfg.provider, "model": cfg.model, "tokens": result.tokens}


# ── AI-analyst report config ────────────────────────────────────────────────────

@router.get("/ai", summary="Get AI configuration (key masked)")
async def get_ai_settings(org_id: str = Depends(require_org)) -> dict:
    return _status("ai")


@router.post("/ai", summary="Update AI configuration")
async def set_ai_settings(payload: AISettingsIn, request: Request, org_id: str = Depends(require_org)) -> dict:
    return _apply_settings("ai", payload, request, org_id)


@router.post("/ai/test", summary="Test the configured AI connection")
async def test_ai_settings(request: Request, org_id: str = Depends(require_org)) -> dict:
    return _run_test("ai", org_id)


# ── Fusion adjudicator config (separate provider/model/key) ─────────────────────

@router.get("/fusion", summary="Get fusion-adjudicator configuration (key masked)")
async def get_fusion_settings(org_id: str = Depends(require_org)) -> dict:
    return _status("fusion")


@router.post("/fusion", summary="Update fusion-adjudicator configuration")
async def set_fusion_settings(payload: AISettingsIn, request: Request, org_id: str = Depends(require_org)) -> dict:
    return _apply_settings("fusion", payload, request, org_id)


@router.post("/fusion/test", summary="Test the configured fusion connection")
async def test_fusion_settings(request: Request, org_id: str = Depends(require_org)) -> dict:
    return _run_test("fusion", org_id)
