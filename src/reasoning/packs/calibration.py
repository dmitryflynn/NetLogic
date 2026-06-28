"""
Confidence calibration policy (Phase 6.5) — interchangeable, not hard-coded.

A fingerprint's *effective* confidence depends on how much we trust its source. Today that's a
simple product (base × source.confidence), but that formula shouldn't be baked into every
subsystem — at scale you'll want to fold in false-positive rate, specificity, recency, and sample
count. So calibration is a swappable policy; `PackLibrary` delegates to one.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from src.reasoning.packs.schema import KnowledgeSource


class CalibrationPolicy(ABC):
    """Maps (base fingerprint confidence, source) → effective confidence in [0, 1]."""

    @abstractmethod
    def calibrate(self, base_confidence: float, source: KnowledgeSource) -> float:
        ...

    def explain(self) -> str:
        return self.__class__.__name__


class MultiplicativeCalibration(CalibrationPolicy):
    """effective = base × source.confidence. The simple Phase 6.5 default."""

    def calibrate(self, base_confidence: float, source: KnowledgeSource) -> float:
        b = max(0.0, min(1.0, base_confidence))
        return round(b * source.confidence, 4)

    def explain(self) -> str:
        return "MultiplicativeCalibration: base × source.confidence"


class FalsePositiveAwareCalibration(CalibrationPolicy):
    """effective = base × source.confidence × (1 − false_positive_rate). A richer example showing
    the formula is swappable without touching any subsystem that asks for a calibrated number."""

    def calibrate(self, base_confidence: float, source: KnowledgeSource) -> float:
        b = max(0.0, min(1.0, base_confidence))
        return round(b * source.confidence * (1.0 - source.false_positive_rate), 4)

    def explain(self) -> str:
        return "FalsePositiveAwareCalibration: base × source.confidence × (1 − fp_rate)"
