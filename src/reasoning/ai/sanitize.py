"""Scrub secrets from AI prompts and transcripts.

Observation text and model rationales can echo banner/env snippets (DB_PASSWORD=,
Bearer tokens, JWTs). Those must not land in `ai_transcript` or LLM payloads.
"""
from __future__ import annotations

import re

_ASSIGN_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"authorization|private[_-]?key|db_password|aws_secret_access_key|"
    r"mysql_pwd|aws_secret)\b(\s*[:=]\s*)(\S+)"
)
_BEARER_RE = re.compile(r"(?i)(bearer\s+)([A-Za-z0-9\-._~+/]+=*)")
_JWT_RE = re.compile(r"eyJ[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}\.[0-9A-Za-z_\-]{8,}")
_AKIA_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_SK_RE = re.compile(r"\bsk[_-](?:live|test)[_-][0-9A-Za-z]{16,}\b")


def sanitize_ai_text(text: str, *, max_len: int = 400) -> str:
    """Return *text* with credential-shaped spans replaced, then truncated."""
    s = str(text or "")
    s = _ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", s)
    s = _BEARER_RE.sub(r"\1[redacted]", s)
    s = _JWT_RE.sub("[redacted-jwt]", s)
    s = _AKIA_RE.sub("[redacted-aws]", s)
    s = _SK_RE.sub("[redacted-sk]", s)
    return s[:max_len]
