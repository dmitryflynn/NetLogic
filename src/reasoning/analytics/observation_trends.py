"""
Observation trends (Phase 7c) — per-entity lifecycle over a snapshot series.

Where the `ObservationDiffer` answers "what changed between *these two* scans?", trend analysis
answers "how has *this entity* behaved over time?" — surfacing drift (slow change) vs. spikes
(sudden change), flapping (noisy assets), and persistence (a CVE that won't go away).

An *entity* is identified by `(node_id, obs_kind)` — stable across scans even when the observation's
value (and thus `obs_id`) changes, so "port 8080 is open" is the same entity whether the banner text
varies or not. Presence in a snapshot = at least one observation of that entity exists.

Pure aggregation over `ObservationSnapshot`s; reuses the `reasoning_state` history (rows per
org/target ordered by `created_at`). No engine change.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ObservationTrend:
    """The lifecycle of one entity across a snapshot series."""
    node_id: str
    obs_kind: str
    host: str
    first_index: int
    last_index: int
    occurrence_count: int          # snapshots it appeared in
    transition_count: int          # present↔absent toggles between consecutive snapshots
    flap_count: int                # present→absent transitions (disappearances after first seen)
    present_now: bool
    age_scans: int                 # last_index − first_index + 1
    age_seconds: Optional[float] = None

    @property
    def is_flapping(self) -> bool:
        return self.flap_count >= 2

    @property
    def is_persistent(self) -> bool:
        return self.occurrence_count >= 3 and self.flap_count == 0

    def to_dict(self) -> dict:
        return {"node_id": self.node_id, "obs_kind": self.obs_kind, "host": self.host,
                "first_index": self.first_index, "last_index": self.last_index,
                "occurrence_count": self.occurrence_count, "transition_count": self.transition_count,
                "flap_count": self.flap_count, "present_now": self.present_now,
                "age_scans": self.age_scans, "age_seconds": self.age_seconds}


class TrendAnalyzer:
    """Builds per-entity `ObservationTrend`s from an ordered snapshot series (oldest → newest)."""

    def analyze(self, snapshots: list, timestamps: Optional[list[float]] = None
                ) -> list[ObservationTrend]:
        if not snapshots:
            return []
        n = len(snapshots)
        # presence[(node_id, obs_kind)] = list[bool] of length n; host captured on first sight.
        presence: dict[tuple[str, str], list[bool]] = {}
        host_of: dict[tuple[str, str], str] = {}
        for i, snap in enumerate(snapshots):
            present_keys = set()
            for so in snap.observations.values():
                key = (so.node_id, so.obs_kind)
                present_keys.add(key)
                host_of.setdefault(key, so.host)
            for key in present_keys:
                vec = presence.setdefault(key, [False] * n)
                vec[i] = True
            # ensure entities seen in earlier snapshots keep their full-length vectors
        # entities that appeared then vanished already have a vector (created on first sight);
        # any key created later still has False for earlier indices.

        trends: list[ObservationTrend] = []
        for key, vec in presence.items():
            indices = [i for i, p in enumerate(vec) if p]
            first_i, last_i = indices[0], indices[-1]
            occ = len(indices)
            transitions = sum(1 for i in range(1, n) if vec[i] != vec[i - 1])
            flaps = sum(1 for i in range(1, n) if vec[i - 1] and not vec[i])  # present→absent
            age_seconds = None
            if timestamps and len(timestamps) == n:
                age_seconds = float(timestamps[last_i] - timestamps[first_i])
            trends.append(ObservationTrend(
                node_id=key[0], obs_kind=key[1], host=host_of.get(key, ""),
                first_index=first_i, last_index=last_i, occurrence_count=occ,
                transition_count=transitions, flap_count=flaps, present_now=vec[-1],
                age_scans=last_i - first_i + 1, age_seconds=age_seconds))
        # deterministic ordering
        trends.sort(key=lambda t: (t.host, t.node_id, t.obs_kind))
        return trends


def trend_report(trends: list[ObservationTrend]) -> str:
    """Human summary highlighting flapping (noisy) and persistent entities."""
    flapping = [t for t in trends if t.is_flapping]
    persistent = [t for t in trends if t.is_persistent]
    lines = ["## Observation Trends", ""]
    if flapping:
        lines.append("### Flapping (noisy)")
        for t in flapping:
            host = f"`{t.host}` " if t.host else ""
            lines.append(f"- {host}{t.node_id} [{t.obs_kind}] — flapped {t.flap_count}×")
        lines.append("")
    if persistent:
        lines.append("### Persistent")
        for t in persistent:
            host = f"`{t.host}` " if t.host else ""
            age = f"{t.age_seconds:.0f}s" if t.age_seconds is not None else f"{t.age_scans} scans"
            lines.append(f"- {host}{t.node_id} [{t.obs_kind}] — present {t.occurrence_count}× over {age}")
        lines.append("")
    if not flapping and not persistent:
        lines.append("No notable trends (no flapping or long-persistent entities).")
    return "\n".join(lines).rstrip() + "\n"
