"""
NetLogic API — per-org AI settings.

Lets each organisation configure its OWN LLM provider / API key / model from the
dashboard. Settings are stored PER-ORG via api.settings_store (Postgres in
production, in-memory for desktop), with the key SEALED at rest (api.crypto).
The owning org's key is resolved at scan time, so one tenant's credentials never
leak into another tenant's scan.

Security: the API key is WRITE-ONLY. GET never returns it, only whether one is
set plus a short masked hint. All endpoints require a valid JWT (org scope).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.auth.dependencies import require_org
from api.auth.rate_limit import settings_limiter
from api.middleware.audit import audit_log
from src.ai_analyst import ALLOWED_PROVIDERS, PROVIDER_PRESETS

router = APIRouter(prefix="/settings", tags=["settings"])

_ROLES = ("ai",)


def _mask(key: str) -> str:
    if not key:
        return ""
    return (key[:4] + "…" + key[-4:]) if len(key) > 12 else "set"


def _status(org_id: str, role: str = "ai") -> dict:
    """Current config for an org's role as the scanner sees it (key never exposed)."""
    from src import ai_analyst  # noqa: PLC0415

    cfg = ai_analyst.config_for_org(org_id, role).resolve()
    return {
        "role": role,
        "provider": cfg.provider,
        "model": cfg.model or "",
        "base_url": cfg.base_url or "",
        "key_set": bool(cfg.api_key),
        "key_hint": _mask(cfg.api_key or ""),
        "providers": sorted(ALLOWED_PROVIDERS),
        "presets": {p: {"base_url": v[0], "model": v[1]} for p, v in PROVIDER_PRESETS.items()},
    }


class AISettingsIn(BaseModel):
    provider: str = Field(..., max_length=32, description="openrouter|openai|anthropic|kimi|qwen|groq|gemini|ollama|custom")
    # Omit or leave empty to KEEP the existing stored key (write-only field).
    api_key: Optional[str] = Field(None, max_length=512)
    model: Optional[str] = Field(None, max_length=128)
    base_url: Optional[str] = Field(None, max_length=256)


def _apply_settings(role: str, payload: "AISettingsIn", request: Request, org_id: str) -> dict:
    if not settings_limiter.allow(org_id):
        raise HTTPException(status_code=429, detail="Too many settings updates. Slow down.")
    from api.settings_store import org_settings_store  # noqa: PLC0415

    provider = (payload.provider or "").strip().lower()
    if provider not in ALLOWED_PROVIDERS:
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported provider '{provider}'. Use one of: {', '.join(sorted(ALLOWED_PROVIDERS))}.",
        )

    base_url = payload.base_url.strip() if payload.base_url is not None else None
    if provider == "custom":
        existing = org_settings_store.get(org_id, role)
        if not (base_url or (existing or {}).get("base_url")):
            raise HTTPException(status_code=422, detail="The 'custom' provider requires a base_url.")

    # api_key semantics: None → keep existing; "" → clear; non-empty → set+seal.
    api_key = payload.api_key.strip() if payload.api_key is not None else None
    keep_key = payload.api_key is None
    try:
        org_settings_store.put(
            org_id, role, provider=provider,
            model=payload.model.strip() if payload.model is not None else None,
            base_url=base_url, api_key=api_key or None, keep_key=keep_key,
        )
    except Exception as exc:
        from api.crypto import SecretsKeyError  # noqa: PLC0415
        if isinstance(exc, SecretsKeyError):
            # Production misconfig (no encryption key) — never store plaintext.
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        raise

    audit_log(f"{role}_settings_updated", org_id=org_id, provider=provider,
              ip=request.client.host if request.client else "")
    return _status(org_id, role)


def _run_test(role: str, org_id: str) -> dict:
    if not settings_limiter.allow(org_id):
        raise HTTPException(status_code=429, detail="Too many test requests. Slow down.")
    from src.ai_analyst import analyze, config_for_org  # noqa: PLC0415
    cfg = config_for_org(org_id, role).resolve()
    usable, reason = cfg.is_usable()
    if not usable:
        return {"ok": False, "error": reason}
    result = analyze({"_connectivity_test": "Reply with the single word: OK."}, cfg)
    if result.error:
        return {"ok": False, "error": result.error, "provider": cfg.provider, "model": cfg.model}
    return {"ok": True, "provider": cfg.provider, "model": cfg.model, "tokens": result.tokens}


# ── AI-analyst report config (per-org) ──────────────────────────────────────────

@router.get("/ai", summary="Get AI configuration (key masked)")
async def get_ai_settings(org_id: str = Depends(require_org)) -> dict:
    return _status(org_id, "ai")


@router.post("/ai", summary="Update AI configuration")
async def set_ai_settings(payload: AISettingsIn, request: Request, org_id: str = Depends(require_org)) -> dict:
    return _apply_settings("ai", payload, request, org_id)


@router.post("/ai/test", summary="Test the configured AI connection")
async def test_ai_settings(request: Request, org_id: str = Depends(require_org)) -> dict:
    return _run_test("ai", org_id)


