"""Cooperative cancel: JobCancelled must not be swallowed as a generic error."""
from __future__ import annotations


def is_job_cancelled(exc: BaseException) -> bool:
    return type(exc).__name__ == "JobCancelled"


def reraise_if_cancelled(exc: BaseException) -> None:
    if is_job_cancelled(exc):
        raise exc
