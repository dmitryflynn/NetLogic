"""
Fusion layer — the real-model adapter ("reality wrapper").

Turns the existing src.ai_analyst transport into the `complete(system, user) -> str`
contract the fusion pipeline expects, with the operational hardening LLMs demand:

  • JSON robustness — `robust_json_array()` aggressively recovers a JSON array from
    messy model output: strips ```json fences and surrounding prose, removes trailing
    commas, and tries several parses before giving up.
  • Transient resilience — `make_completer()` retries 429/502/503/504 and network
    blips using ai_analyst's own retry policy/backoff (reused, not reimplemented),
    so a batched benchmark run survives provider hiccups.
  • Streaming — `make_stream_completer()` yields token deltas via `on_token(delta)`
    callback, enabling progressive "ai" SSE events so the front end shows markdown
    as it arrives rather than freezing at 99 %.

The model/key/provider come from the operator's configured ai_analyst settings; this
module never handles the raw key.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

log = logging.getLogger("netlogic.fusion.ai")

CompleteFn = Callable[[str, str], str]
StreamCompleteFn = Callable[[str, str, Callable[[str], None]], str]


# ── JSON robustness ─────────────────────────────────────────────────────────────

def _try_load_array(s: str):
    try:
        v = json.loads(s)
        return v if isinstance(v, list) else None
    except json.JSONDecodeError:
        return None


def robust_json_array(text: str) -> Optional[list]:
    """Best-effort extraction of a JSON array from messy LLM output."""
    if not text:
        return None
    t = text.strip()
    # 1. strip a leading/trailing markdown code fence
    t = re.sub(r"^```(?:json)?\s*", "", t, flags=re.I)
    t = re.sub(r"\s*```$", "", t).strip()

    # 2. direct parse
    arr = _try_load_array(t)
    if arr is not None:
        return arr

    # 3. carve out the outermost [ ... ] and retry, with trailing-comma cleanup
    m = re.search(r"\[.*\]", t, re.S)
    if m:
        chunk = m.group(0)
        arr = _try_load_array(chunk)
        if arr is not None:
            return arr
        cleaned = re.sub(r",(\s*[\]}])", r"\1", chunk)   # kill trailing commas
        arr = _try_load_array(cleaned)
        if arr is not None:
            return arr
    return None


# ── Retrying real-model completer ───────────────────────────────────────────────

def make_completer(cfg=None) -> CompleteFn:
    """Return a `complete(system, user) -> raw_text` backed by the configured model,
    retrying transient provider errors (429/502/503/504/network) with backoff."""

    def complete(system: str, user: str) -> str:
        from src import ai_analyst as aa  # noqa: PLC0415
        c = cfg or aa.config_from_env().resolve()
        usable, reason = c.is_usable()
        if not usable:
            raise RuntimeError(reason)
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]

        last = ""
        last_was_rate_limit = False
        for attempt in range(aa._MAX_AI_ATTEMPTS):
            try:
                res = (aa._call_anthropic(c, messages) if c.api_style == "anthropic"
                       else aa._call_openai(c, messages))
                if res.error:
                    raise RuntimeError(res.error)
                return res.markdown
            except aa._TransientAIError as e:
                last = str(e)
            except urllib.error.HTTPError as e:
                if e.code in aa._RETRYABLE_STATUS:
                    body = ""
                    try:
                        body = e.read().decode("utf-8", errors="replace")[:300]
                    except Exception:
                        pass
                    last = f"HTTP {e.code}"
                    if body:
                        last += f" — {body}"
                    last_was_rate_limit = e.code in (429, 529)
                else:
                    raise
            except urllib.error.URLError as e:
                last = f"network error: {e.reason}"
            if attempt < aa._MAX_AI_ATTEMPTS - 1:
                if last_was_rate_limit:
                    time.sleep(30.0)
                else:
                    time.sleep(aa._RETRY_BACKOFF_SECONDS[min(attempt, len(aa._RETRY_BACKOFF_SECONDS) - 1)])

        hint = ""
        last_lower = last.lower()
        if "billing" in last_lower or "payment" in last_lower:
            hint = (" Billing issue detected. Google requires a billing account "
                    "on the Cloud project even for Gemini free tier. "
                    "Enable the Generative Language API and set up billing at "
                    "https://console.cloud.google.com/apis/library/generativelanguage.googleapis.com")
        elif "429" in last or "quota" in last_lower or "rate" in last_lower:
            hint = (" The API returned a rate-limit or quota error. "
                    "Gemini free tier: 10 requests/minute, 1500/day. "
                    "Wait a moment and retry, or upgrade your API plan.")
        raise RuntimeError(f"AI transient failure after {aa._MAX_AI_ATTEMPTS} attempts: {last}.{hint}")

    return complete


# ── Streaming completer (token-by-token SSE) ─────────────────────────────────


def _stream_openai(cfg, messages: list[dict], on_token: Callable[[str], None]) -> str:
    """Stream tokens from an OpenAI-compatible API with `stream: true`.

    Calls ``on_token(delta)`` for each text delta received via SSE.
    Returns the full accumulated text.
    """
    url = cfg.base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Content-Type": "application/json",
    }
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    if cfg.provider == "openrouter":
        headers["HTTP-Referer"] = "https://github.com/netlogic"
        headers["X-Title"] = "NetLogic"

    payload = {
        "model": cfg.model,
        "messages": messages,
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
        "stream": True,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    full_text = ""
    with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
        for raw_line in resp:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line.startswith("data: "):
                continue
            data_str = line[6:]
            if data_str == "[DONE]":
                break
            try:
                obj = json.loads(data_str)
                for choice in obj.get("choices", []):
                    delta = choice.get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        full_text += content
                        on_token(content)
            except json.JSONDecodeError:
                pass

    return full_text


def _stream_anthropic(cfg, messages: list[dict], on_token: Callable[[str], None]) -> str:
    """Stream tokens from an Anthropic-style API via SSE.

    Anthropic Messages API streaming format::
        event: content_block_delta
        data: {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "..."}}

    Calls ``on_token(delta)`` for each text delta.
    Returns the full accumulated text.
    """
    url = cfg.base_url.rstrip("/") + "/v1/messages"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": cfg.api_key,
        "anthropic-version": "2023-06-01",
    }
    system = next((m["content"] for m in messages if m["role"] == "system"), "")
    chat = [m for m in messages if m["role"] != "system"]

    payload = {
        "model": cfg.model,
        "system": system,
        "messages": chat,
        "max_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
        "stream": True,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    full_text = ""
    with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
        event_type = None
        for raw_line in resp:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if line.startswith("event: "):
                event_type = line[7:]
                continue
            if line.startswith("data: "):
                data_str = line[6:]
                if data_str == "[DONE]":
                    break
                if event_type == "content_block_delta":
                    try:
                        obj = json.loads(data_str)
                        delta = obj.get("delta", {})
                        if delta.get("type") == "text_delta":
                            content = delta.get("text", "")
                            if content:
                                full_text += content
                                on_token(content)
                    except json.JSONDecodeError:
                        pass

    return full_text


def make_stream_completer(cfg=None) -> StreamCompleteFn:
    """Return a ``stream_complete(system, user, on_token) -> full_text`` backed by
    the configured model, retrying transient provider errors."""

    def stream_complete(system: str, user: str, on_token: Callable[[str], None]) -> str:
        from src import ai_analyst as aa  # noqa: PLC0415
        c = cfg or aa.config_from_env().resolve()
        usable, reason = c.is_usable()
        if not usable:
            raise RuntimeError(reason)
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]

        last = ""
        last_was_rate_limit = False
        for attempt in range(aa._MAX_AI_ATTEMPTS):
            try:
                if c.api_style == "anthropic":
                    return _stream_anthropic(c, messages, on_token)
                return _stream_openai(c, messages, on_token)
            except aa._TransientAIError as e:
                last = str(e)
            except urllib.error.HTTPError as e:
                if e.code in aa._RETRYABLE_STATUS:
                    body = ""
                    try:
                        body = e.read().decode("utf-8", errors="replace")[:300]
                    except Exception:
                        pass
                    last = f"HTTP {e.code}"
                    if body:
                        last += f" — {body}"
                    last_was_rate_limit = e.code in (429, 529)
                else:
                    raise
            except urllib.error.URLError as e:
                last = f"network error: {e.reason}"
            if attempt < aa._MAX_AI_ATTEMPTS - 1:
                # Rate limits need longer cooldown than transient blips
                if last_was_rate_limit:
                    time.sleep(30.0)
                else:
                    time.sleep(aa._RETRY_BACKOFF_SECONDS[min(attempt, len(aa._RETRY_BACKOFF_SECONDS) - 1)])

        # Build an actionable message
        hint = ""
        last_lower = last.lower()
        if "billing" in last_lower or "payment" in last_lower:
            hint = (" Billing issue detected. Google requires a billing account "
                    "on the Cloud project even for Gemini free tier. "
                    "Enable the Generative Language API and set up billing at "
                    "https://console.cloud.google.com/apis/library/generativelanguage.googleapis.com")
        elif "429" in last or "quota" in last_lower or "rate" in last_lower:
            hint = (" The API returned a rate-limit or quota error. "
                    "Gemini free tier: 10 requests/minute, 1500/day. "
                    "Wait a moment and retry, or upgrade your API plan.")
        raise RuntimeError(f"AI transient failure after {aa._MAX_AI_ATTEMPTS} attempts: {last}.{hint}")

    return stream_complete
