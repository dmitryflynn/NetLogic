"""
NetLogic — Fusion layer (sensors → deterministic gate → AI adjudication).

Pipeline:
  1. Sensors emit evidence-bearing `Signal`s (signals.py).
  2. A deterministic `adjudicate()` gate auto-confirms / auto-discards / routes the
     gray band, with KEV/probe-confirmed criticals pinned UN-DROPPABLE (gate.py).
  3. AI adjudication + graph-based synthesis (adjudicator.py, synthesis.py).
"""

from src.fusion.signals import Signal
from src.fusion.gate import Verdict, adjudicate
from src.fusion.adjudicator import run_adjudication, AIVerdict

__all__ = ["Signal", "Verdict", "adjudicate", "run_adjudication", "AIVerdict"]
