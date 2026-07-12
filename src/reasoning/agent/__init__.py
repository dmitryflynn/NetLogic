"""AI-led investigation agent — engine baselines; AI drives tools.

Invariant: the AI never executes network I/O. It only selects tools + args.
The deterministic ToolRuntime validates and executes.
"""
from __future__ import annotations

from src.reasoning.agent.loop import InvestigationAgent, AgentResult
from src.reasoning.agent.surface import build_surface_summary

__all__ = ["InvestigationAgent", "AgentResult", "build_surface_summary"]
