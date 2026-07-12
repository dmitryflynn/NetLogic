"""Shared exception for the AI proposal-pipeline input boundary."""
from __future__ import annotations


class ValidationError(Exception):
    """Raised for any input a Normalizer/Verifier stage cannot validate. Mirrors the Phase 4
    `proposal_parser.ValidationError` contract: callers never see an uncontrolled exception."""
