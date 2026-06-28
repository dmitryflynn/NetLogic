"""
NetLogic reasoning subsystem — the persistent, hierarchical reasoning state.
"""
from __future__ import annotations

from src.reasoning.budget import BudgetManager
from src.reasoning.builder import build_reasoning_state, refresh_beliefs, safe_build_reasoning_state
from src.reasoning.candidate import Candidate, RankedCandidate
from src.reasoning.capability_registry import Capability, CapabilityRegistry, open_question_tags
from src.reasoning.compiler import Compiler
from src.reasoning.cross_host import (
    AuthDecision,
    CrossHostEdge,
    CrossHostGraph,
    ScopeAuthorizer,
    derive_cross_host_edges,
)
from src.reasoning.world_state import (
    EnvironmentGraph,
    HostManager,
    HostReasoner,
    WorldState,
)
from src.reasoning.confidence import Belief, ConfidenceEngine, apply_decay
from src.reasoning.decision_policy import (
    BudgetPolicy,
    DecisionPolicy,
    DefaultDecisionPolicy,
    FastPolicy,
    GreedyPolicy,
    RankedAction,
)
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
from src.reasoning.learned_patterns import (
    CandidatePattern,
    LearnedPattern,
    PatternExtractor,
    PatternRecall,
    PatternValidator,
    PriorityHint,
)
from src.reasoning.memory import MemoryStore, ProbeRecord
from src.reasoning.objective import Objective, ObjectiveDAG
from src.reasoning.observation import Observation
from src.reasoning.playbooks import Playbook, PlaybookInstantiator, PlaybookLoader, PlaybookRegistry
from src.reasoning.primitive_registry import Primitive, PrimitiveRegistry, default_registry
from src.reasoning.provenance import (
    InferenceHypothesisEdge,
    ObservationInferenceEdge,
    ProvenanceBuilder,
    ProvenanceGraph,
    ProvenanceTracer,
)
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
    "BudgetPolicy",
    "Candidate",
    "Capability",
    "CapabilityRegistry",
    "Compiler",
    "Condition",
    "ConditionOp",
    "AuthDecision",
    "ConfidenceEngine",
    "CrossHostEdge",
    "CrossHostGraph",
    "DecisionPolicy",
    "DefaultDecisionPolicy",
    "Dependency",
    "EnvironmentGraph",
    "FastPolicy",
    "GreedyPolicy",
    "HostManager",
    "HostReasoner",
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
    "LearnedPattern",
    "LearnedPatterns",
    "MemoryStore",
    "PatternExtractor",
    "PatternRecall",
    "PatternValidator",
    "PriorityHint",
    "Objective",
    "ObjectiveDAG",
    "Observation",
    "Playbook",
    "PlaybookInstantiator",
    "PlaybookLoader",
    "PlaybookRegistry",
    "PlannerFeedback",
    "PlanWalker",
    "InferenceHypothesisEdge",
    "ObservationInferenceEdge",
    "Primitive",
    "PrimitiveRegistry",
    "ProbeCost",
    "ProvenanceBuilder",
    "ProvenanceGraph",
    "ProvenanceTracer",
    "ProbePlan",
    "ProbePlanGraph",
    "ProbeRecord",
    "ProbeSpec",
    "RankedAction",
    "RankedCandidate",
    "ReasoningState",
    "ReconDirector",
    "Reflect",
    "Scheduler",
    "ScoredAction",
    "ScopeAuthorizer",
    "SensorStep",
    "StepContext",
    "StopCondition",
    "derive_cross_host_edges",
    "StrategyManager",
    "TraceMetadata",
    "TraceStep",
    "WorldModel",
    "WorldState",
    "apply_decay",
    "build_reasoning_state",
    "default_registry",
    "node_id",
    "refresh_beliefs",
    "safe_build_reasoning_state",
]
