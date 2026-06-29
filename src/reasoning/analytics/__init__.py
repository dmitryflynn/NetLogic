"""Reasoning analytics (Phase 7c) — time-series analysis over observation snapshots.

A SEPARATE domain from pairwise change detection (`src/reasoning/change_detection.py`): the differ
compares two snapshots; analytics studies a *series* and will grow into forecasting / anomaly
detection / asset aging. Kept in its own package so that growth doesn't couple back to the differ.
"""
from src.reasoning.analytics.observation_trends import (
    ObservationTrend,
    TrendAnalyzer,
    trend_report,
)

__all__ = ["ObservationTrend", "TrendAnalyzer", "trend_report"]
