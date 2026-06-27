"""
NetLogic reasoning subsystem — the persistent, hierarchical reasoning state.
"""
from __future__ import annotations

from src.reasoning.budget import BudgetManager
from src.reasoning.builder import build_reasoning_state, refresh_beliefs, safe_build_reasoning_state
from src.reasoning.compiler import Compiler
from src.reasoning.confidence import Belief, ConfidenceEngine, apply_decay
from src.reasoning.decision_policy import DecisionPolicy, DefaultDecisionPolicy, RankedAction
from src.reasoning.director import ReconDirector
from src.reasoning.evidence_graph import EntityNode, EvidenceGraph, node_id
from src.reasoning.execution_kernel import ExecutionKernel
from src.reasoning.execution_planner import ExecutionPlanner
from src.reasoning.explanation import Explanation
from src.reasoning.hypothesis import Hypothesis, HypothesisEngine
from src.reasoning.intent import EvidenceType, Intent, IntentConstraints, ProbeCost, StopCondition
from src.reasoning.investigation_graph import (
    Dependency,
    DependencyType,
    EndpointInfo,
    EndpointResolver,
    EvidenceRequest,
    InvestigationGraph,
)
from src.reasoning.memory import MemoryStore, ProbeRecord
from src.reasoning.objective import Objective, ObjectiveDAG
from src.reasoning.observation import Observation
from src.reasoning.playbooks import Playbook, PlaybookInstantiator, PlaybookLoader, PlaybookRegistry
from src.reasoning.primitive_registry import Primitive, PrimitiveRegistry, default_registry
from src.reasoning.probe_plan import (
    Condition,
    ConditionOp,
    PlanWalker,
    ProbePlan,
    ProbePlanGraph,
    ProbeSpec,
)
from src.reasoning.reflect import PlannerFeedback, Reflect
from src.reasoning.registry import SensorStep, StepContext
from src.reasoning.scheduler import Scheduler, ScoredAction
from src.reasoning.state import (
    ExecutionState,
    InvestigationState,
    LearnedPatterns,
    ReasoningState,
    WorldModel,
)
from src.reasoning.strategy import StrategyManager
from src.reasoning.trace import ExecutionResult, TraceMetadata, TraceStep

__all__ = [
    "Belief",
    "BudgetManager",
    "Compiler",
    "Condition",
    "ConditionOp",
    "ConfidenceEngine",
    "DecisionPolicy",
    "DefaultDecisionPolicy",
    "Dependency",
    "DependencyType",
    "EndpointInfo",
    "EndpointResolver",
    "EntityNode",
    "EvidenceGraph",
    "EvidenceRequest",
    "EvidenceType",
    "ExecutionKernel",
    "ExecutionPlanner",
    "ExecutionResult",
    "ExecutionState",
    "Explanation",
    "Hypothesis",
    "HypothesisEngine",
    "Intent",
    "IntentConstraints",
    "InvestigationGraph",
    "InvestigationState",
    "LearnedPatterns",
    "MemoryStore",
    "Objective",
    "ObjectiveDAG",
    "Observation",
    "Playbook",
    "PlaybookInstantiator",
    "PlaybookLoader",
    "PlaybookRegistry",
    "PlannerFeedback",
    "PlanWalker",
    "Primitive",
    "PrimitiveRegistry",
    "ProbeCost",
    "ProbePlan",
    "ProbePlanGraph",
    "ProbeRecord",
    "ProbeSpec",
    "RankedAction",
    "ReasoningState",
    "ReconDirector",
    "Reflect",
    "Scheduler",
    "ScoredAction",
    "SensorStep",
    "StepContext",
    "StopCondition",
    "StrategyManager",
    "TraceMetadata",
    "TraceStep",
    "WorldModel",
    "apply_decay",
    "build_reasoning_state",
    "default_registry",
    "node_id",
    "refresh_beliefs",
    "safe_build_reasoning_state",
]
