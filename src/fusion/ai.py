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

The model/key/provider come from the operator's configured ai_analyst settings; this
module never handles the raw key.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
from typing import Callable, Optional

log = logging.getLogger("netlogic.fusion.ai")

CompleteFn = Callable[[str, str], str]


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
                    last = f"HTTP {e.code}"
                else:
                    raise
            except urllib.error.URLError as e:
                last = f"network error: {e.reason}"
            if attempt < aa._MAX_AI_ATTEMPTS - 1:
                time.sleep(aa._RETRY_BACKOFF_SECONDS[min(attempt, len(aa._RETRY_BACKOFF_SECONDS) - 1)])

        raise RuntimeError(f"AI transient failure after {aa._MAX_AI_ATTEMPTS} attempts: {last}")

    return complete
