"""
Probe memory — an append-only event log of every probe the engine considers.

See docs/REASONING_ENGINE_DESIGN.md §3.3 / §9. Each probe is reduced to a normalized key;
the MemoryStore records the outcome (success, latency, information gained, whether it rested
on a false assumption) so the planner never re-issues an equivalent probe and can learn from
prior failures.

The log is **event-oriented**: every record is an immutable, timestamped event, *appended*
— never mutated or overwritten. Re-probing the same target produces a second event rather
than replacing the first, which is what makes replay, UI timelines, and reasoning debugging
(design §10.2) possible later. Phase 0 ships the store standalone (unwired); the
ExecutionKernel consults it in Phase 3.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass(frozen=True)
class ProbeRecord:
    """One immutable probe-outcome event. Frozen so a recorded event can never change."""
    probe_key: str
    success: bool = False
    latency_ms: float = 0.0
    info_gained: float = 0.0           # information gain actually realized, 0..1
    result_summary: str = ""
    false_assumption: bool = False     # the probe was premised on a belief later contradicted
    timestamp: float = field(default_factory=time.time)


class MemoryStore:
    """Append-only event log of probe outcomes, keyed by normalized probe identity.

    The key is derived from the *semantic* identity of a probe (transport, protocol,
    target host/port, and the structured request) so two specs that would send the same
    request share a key regardless of incidental fields (id, timestamps, cost estimates).
    """

    # Fields that define a probe's semantic identity. Everything else (id, purpose,
    # cost estimates, timeouts) is incidental and excluded from the dedup key.
    _IDENTITY_FIELDS = ("transport", "protocol", "target_host", "target_port", "request_spec")

    def __init__(self) -> None:
        self._events: list[ProbeRecord] = []          # append-only, chronological
        self._keys: set[str] = set()                  # fast membership for dedup

    @classmethod
    def probe_key(cls, spec: dict) -> str:
        """Normalize a probe spec into a stable dedup key."""
        identity = {k: spec.get(k) for k in cls._IDENTITY_FIELDS}
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]

    def seen(self, spec: dict) -> bool:
        """True if an equivalent probe has already been recorded at least once."""
        return self.probe_key(spec) in self._keys

    def latest(self, spec: dict) -> Optional[ProbeRecord]:
        """The most recent recorded event for an equivalent probe, or None."""
        key = self.probe_key(spec)
        for rec in reversed(self._events):
            if rec.probe_key == key:
                return rec
        return None

    def record(self, spec: dict, *, success: bool, latency_ms: float = 0.0,
               info_gained: float = 0.0, result_summary: str = "",
               false_assumption: bool = False) -> ProbeRecord:
        """Append a new immutable outcome event for a probe and return it.

        Never overwrites a prior event — re-probing the same target appends a second event,
        preserving the full history for replay and debugging.
        """
        rec = ProbeRecord(
            probe_key=self.probe_key(spec),
            success=success,
            latency_ms=float(latency_ms),
            info_gained=max(0.0, min(1.0, float(info_gained))),
            result_summary=result_summary,
            false_assumption=bool(false_assumption),
        )
        self._events.append(rec)
        self._keys.add(rec.probe_key)
        return rec

    def events(self) -> list[ProbeRecord]:
        """The full chronological event log (for replay / timelines)."""
        return list(self._events)

    def failures(self) -> list[ProbeRecord]:
        """Failed events — fuel for the planner to avoid repeating dead ends."""
        return [r for r in self._events if not r.success]

    def __len__(self) -> int:
        return len(self._events)

    # ── Serialization (rides along with ReasoningState persistence) ───────────────
    def to_dict(self) -> dict:
        """Serialize as an ordered event list under a stable envelope."""
        return {"events": [asdict(r) for r in self._events]}

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "MemoryStore":
        store = cls()
        allowed = {f for f in ProbeRecord.__dataclass_fields__}
        for rec in (data or {}).get("events", []):
            r = ProbeRecord(**{k: v for k, v in rec.items() if k in allowed})
            store._events.append(r)
            store._keys.add(r.probe_key)
        return store
