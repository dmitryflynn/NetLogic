"""Technology Pack knowledge system (Phase 6.5).

One YAML per technology, compiled once into immutable CompiledPacks that plug into the existing
reasoning engine (inference rules, capabilities, confidence priors, priority hints). Supports
inheritance, aliases, composition, and source-calibrated confidence.
"""
from src.reasoning.packs.compiler import PackCompiler, PackLibrary
from src.reasoning.packs.schema import (
    CompiledPack,
    Fingerprints,
    KnowledgeSource,
    PackCapability,
    StoppingSpec,
)

__all__ = [
    "CompiledPack",
    "Fingerprints",
    "KnowledgeSource",
    "PackCapability",
    "PackCompiler",
    "PackLibrary",
    "StoppingSpec",
]
