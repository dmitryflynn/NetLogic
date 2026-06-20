"""
NetLogic — Fusion layer (vertical slice, experimental).

This package is the "sensors → deterministic gate → (AI) adjudication" core from
the architecture design. It is SELF-CONTAINED and not yet wired into the live scan
pipeline — it can be imported, tested, and measured in isolation. Deleting this
package fully reverts the experiment; no existing module imports it.

Pipeline (this slice implements stages 1–2):
  1. Sensors emit evidence-bearing `Signal`s (signals.py).
  2. A deterministic `adjudicate()` gate auto-confirms / auto-discards / routes the
     gray band, with KEV/probe-confirmed criticals pinned UN-DROPPABLE (gate.py).
  3. (next increments) AI adjudication of the gray band + graph-based synthesis.
"""

from src.fusion.signals import Signal
from src.fusion.gate import Verdict, adjudicate
from src.fusion.adjudicator import run_adjudication, AIVerdict

__all__ = ["Signal", "Verdict", "adjudicate", "run_adjudication", "AIVerdict"]
