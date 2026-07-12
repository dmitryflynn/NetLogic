"""
NetLogic reasoning subsystem — the persistent, hierarchical reasoning state.
"""
from __future__ import annotations

from src.reasoning.budget import BudgetManager
from src.reasoning.builder import build_reasoning_state, refresh_beliefs, safe_build_reasoning_state
from src.reasoning.actions import (
    Action,
    ActionDescriptor,
    ActionLibrary,
    ActionSemantics,
    Predicate,
    RiskTier,
)
from src.reasoning.action_gate import (
    ActionGate,
    AuditLog,
    AuthorizationToken,
    GateContext,
    GateDecision,
)
from src.reasoning.candidate import Candidate, RankedCandidate
from src.reasoning.capability_registry import Capability, CapabilityRegistry
from src.reasoning.investigation_memory import InvestigationMemory, StrategyAttempt
from src.reasoning.investigation_planner import (
    GoalPlanner,
    InvestigationPlan,
    PlanCompiler,
    PlanEvaluator,
    PlanExplainer,
    PlannedStep,
)
from src.reasoning.strategies import (
    InvestigationTemplate,
    Strategy,
    StrategyRegistry,
)
from src.reasoning.change_detection import (
    DeltaAnalyzer,
    DeltaEvent,
    DeltaTyper,
    ObservationDiffer,
    ObservationSnapshot,
    ReinvestigationSeed,
    ScanDelta,
    delta_report,
    diff_states,
    seed_from_delta,
)
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
    LearnedPattern,
    PatternExtractor,
    PatternRecall,
    PatternValidator,
    PriorityHint,
)
from src.reasoning.memory import MemoryStore, ProbeRecord
from src.reasoning.multi_host import (
    dispatch as dispatch_hosts,
    expand_world,
    host_expansion_candidates,
    make_host_candidate,
)
from src.reasoning.objective import Objective, ObjectiveDAG, ObjectiveSource
from src.reasoning.observation import Observation
from src.reasoning.postcondition import ExecutionOutcome, assert_effects, proof_observation
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
    "Action",
    "ActionDescriptor",
    "ActionGate",
    "ActionLibrary",
    "ActionSemantics",
    "AuditLog",
    "AuthorizationToken",
    "Belief",
    "GateContext",
    "GateDecision",
    "GoalPlanner",
    "InvestigationMemory",
    "InvestigationPlan",
    "InvestigationTemplate",
    "PlanCompiler",
    "PlanEvaluator",
    "PlanExplainer",
    "PlannedStep",
    "Predicate",
    "RiskTier",
    "Strategy",
    "StrategyAttempt",
    "StrategyRegistry",
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
    "DeltaAnalyzer",
    "DeltaEvent",
    "DeltaTyper",
    "Dependency",
    "EnvironmentGraph",
    "ObservationDiffer",
    "ObservationSnapshot",
    "ReinvestigationSeed",
    "ScanDelta",
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
    "ExecutionOutcome",
    "Objective",
    "ObjectiveDAG",
    "ObjectiveSource",
    "Observation",
    "Playbook",
    "PlaybookInstantiator",
    "assert_effects",
    "proof_observation",
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
    "delta_report",
    "diff_states",
    "dispatch_hosts",
    "seed_from_delta",
    "expand_world",
    "host_expansion_candidates",
    "make_host_candidate",
    "node_id",
    "refresh_beliefs",
    "safe_build_reasoning_state",
]
