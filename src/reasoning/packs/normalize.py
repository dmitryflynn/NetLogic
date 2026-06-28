"""
Observation normalization (Phase 6.5) — canonicalize BEFORE fingerprint matching.

Raw observations vary in trivial ways that would otherwise force every fingerprint to enumerate
variants forever:

    "Server: nginx"  "Server:nginx"  "Server: nginx/1.24"  "Server: nginx (Ubuntu)"  "SERVER: NGINX"

This layer reduces them to a canonical form so one fingerprint (`server: nginx`) matches them all.
It sits between raw evidence and matching:

    raw observation → Normalizer.canonicalize → canonical text → fingerprint match

The normalizer is deterministic and rule-driven (no IO, no state). Version stripping is conservative
and opt-in per call so version-specific fingerprints can still match when they need to.
"""
from __future__ import annotations

import re

_WS = re.compile(r"\s+")
_HEADER_COLON = re.compile(r"\s*:\s*")
# product tokens whose trailing version / OS parenthetical is noise for detection
_VERSIONED = re.compile(
    r"\b(server|x-powered-by|via)(: )([a-z0-9._+-]+?)([/ ]v?[0-9][a-z0-9._-]*| \([^)]*\))",
)


def canonicalize(text: str) -> str:
    """Lower-case, collapse whitespace, and normalize `key: value` spacing. Lossless for matching
    (only formatting is unified)."""
    if not text:
        return ""
    t = text.lower()
    t = _HEADER_COLON.sub(": ", t)        # "server:nginx" / "server :  nginx" → "server: nginx"
    t = _WS.sub(" ", t).strip()
    return t


def strip_versions(text: str) -> str:
    """Canonicalize, then drop version numbers / OS parentheticals after product tokens, so
    `server: nginx/1.24 (ubuntu)` → `server: nginx`. Use when a fingerprint is version-agnostic."""
    t = canonicalize(text)
    # repeat until stable (handles "nginx/1.24 (ubuntu)" → "nginx")
    prev = None
    while prev != t:
        prev = t
        t = _VERSIONED.sub(lambda m: m.group(1) + m.group(2) + m.group(3), t)
    return t


class Normalizer:
    """Canonicalizes the parts of a recorded/observed response used for fingerprint matching."""

    def __init__(self, strip_version: bool = True) -> None:
        self.strip_version = strip_version

    def header_blob(self, headers) -> str:
        if isinstance(headers, dict):
            raw = " ".join(f"{k}: {v}" for k, v in headers.items())
        else:
            raw = str(headers or "")
        return strip_versions(raw) if self.strip_version else canonicalize(raw)

    def text_blob(self, text) -> str:
        return canonicalize(str(text or ""))

    def cookie_blob(self, cookies) -> str:
        raw = " ".join(map(str, cookies)) if isinstance(cookies, list) else str(cookies or "")
        return canonicalize(raw)
