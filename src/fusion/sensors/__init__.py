"""
Fusion sensors — each turns observations into evidence-bearing Signals for the gate.

A sensor NEVER decides what's real; it reports what it observed, with provenance,
reliability, and the raw evidence. Adjudication is the gate's (and later the AI's)
job. This keeps the "sensors, not reporters" boundary clean.
"""

from src.fusion.sensors.wappalyzer import HttpResponse, Wappalyzer

__all__ = ["HttpResponse", "Wappalyzer"]
