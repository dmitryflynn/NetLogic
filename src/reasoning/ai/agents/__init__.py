"""Cognitive agents (Track C) — thin LLM-facing producers of typed `AgentTask`s.

Each agent turns a `ReasoningState` into raw proposals; the `AICoordinator` does all validation,
ranking, meta-pruning, and verification. Wave 1: C1 Hypothesis Generator + C11 Counterfactual.
"""
from __future__ import annotations

from src.reasoning.ai.agents.adjudicator import FindingAdjudicator
from src.reasoning.ai.agents.base import (
    CognitiveAgent, Completer, call_completer, observation_ids, world_context,
)
from src.reasoning.ai.agents.counterfactual import CounterfactualReasoner
from src.reasoning.ai.agents.hypothesis_generator import HypothesisGenerator
from src.reasoning.ai.agents.investigation_designer import InvestigationDesigner
from src.reasoning.ai.agents.investigation_planner import InvestigationPlanner

__all__ = [
    "CognitiveAgent",
    "Completer",
    "CounterfactualReasoner",
    "FindingAdjudicator",
    "HypothesisGenerator",
    "InvestigationDesigner",
    "InvestigationPlanner",
    "call_completer",
    "observation_ids",
    "world_context",
]
