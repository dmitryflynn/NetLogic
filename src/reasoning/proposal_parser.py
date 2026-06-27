"""
ProposalParser — turns raw LLM text into validated, bounded proposals.

See the Phase 4 plan §1. Parsing/validation is split out of `AIProposer` so it can be fuzzed and
audited in isolation. The parser is the security gate on the AI input boundary: it is **total**
— for ANY input it returns a validated structure or raises `ValidationError`, never an
uncontrolled exception and never partial/garbage state. It enforces size, item-count, depth,
enum-membership, and numeric-sanity bounds.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

_MAX_INPUT_CHARS = 20_000
_MAX_ITEMS = 50
_MAX_CANDIDATES = 24


class ValidationError(Exception):
    """Raised for any input the parser cannot turn into a valid proposal."""


@dataclass(frozen=True)
class FrameworkProposal:
    objective: str
    candidates: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class ValidatedProposal:
    framework_proposals: list[FrameworkProposal] = field(default_factory=list)
    evidence_types: list[str] = field(default_factory=list)


class ProposalParser:
    def __init__(self, evidence_values: set[str]) -> None:
        self._evidence_values = set(evidence_values)

    # ── Decoding (total: returns Any or raises ValidationError) ────────────────────
    def _decode(self, raw: Any) -> Any:
        if not isinstance(raw, str):
            raise ValidationError("input is not text")
        if len(raw) > _MAX_INPUT_CHARS:
            raise ValidationError(f"input exceeds {_MAX_INPUT_CHARS} chars")
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1].rsplit("```", 1)[0] if "\n" in text else text[3:]
            text = text.strip()
        try:
            return json.loads(text)
        except (ValueError, RecursionError) as exc:   # malformed / pathologically nested
            raise ValidationError(f"not valid JSON: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 — any decoder surprise is a validation failure
            raise ValidationError(f"decode failed: {exc}") from exc

    # ── Typed parsers ──────────────────────────────────────────────────────────────
    def parse_framework_proposals(self, raw: Any) -> list[FrameworkProposal]:
        data = self._decode(raw)
        if not isinstance(data, list):
            raise ValidationError("expected a JSON list of proposals")
        out: list[FrameworkProposal] = []
        for item in data[:_MAX_ITEMS]:
            if not isinstance(item, dict):
                continue
            objective = item.get("objective")
            cands = item.get("candidates")
            if not isinstance(objective, str) or not objective or not isinstance(cands, dict):
                continue
            clean: dict[str, float] = {}
            for k, v in list(cands.items())[:_MAX_CANDIDATES]:
                if isinstance(k, str) and isinstance(v, (int, float)):
                    f = float(v)
                    if f == f and f != float("inf") and f > 0:   # finite, positive (NaN-safe)
                        clean[k[:64]] = f
            if clean:
                out.append(FrameworkProposal(objective=objective[:128], candidates=clean))
        return out

    def parse_evidence_types(self, raw: Any) -> list[str]:
        data = self._decode(raw)
        if not isinstance(data, list):
            raise ValidationError("expected a JSON list of evidence-type strings")
        seen: list[str] = []
        for v in data[:_MAX_ITEMS]:
            if isinstance(v, str) and v in self._evidence_values and v not in seen:
                seen.append(v)
        return seen

    def parse(self, raw_hypotheses: Any, raw_intents: Any) -> ValidatedProposal:
        """Best-effort combined parse; each side independently fail-soft to empty."""
        try:
            fps = self.parse_framework_proposals(raw_hypotheses)
        except ValidationError:
            fps = []
        try:
            evs = self.parse_evidence_types(raw_intents)
        except ValidationError:
            evs = []
        return ValidatedProposal(framework_proposals=fps, evidence_types=evs)
