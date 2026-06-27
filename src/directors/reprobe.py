"""Iterative re-probe loop — resolve potential findings via targeted probes.

After fusion pass 1, items with decision='potential' remain. This module
asks the LLM which of those can be resolved by a targeted probe, generates
the probe plan, and returns it so the engine can execute and re-adjudicate.

Fail-soft: returns empty list (potential items stay potential).
Max one re-probe cycle per scan (enforced by caller).
"""

from __future__ import annotations

import json
import logging
from typing import Callable, Optional

log = logging.getLogger("netlogic.directors.reprobe")

SYSTEM = (
    "You are a penetration testing assistant. Given a list of POTENTIAL "
    "(uncertain) security findings, decide which can be resolved by a "
    "targeted HTTP probe and design the probe.\n\n"
    "For each resolvable finding, return a probe plan. A probe plan is a "
    "single raw-HTTP request (no tools) that would return discriminating "
    "evidence confirming or refuting the finding.\n\n"
    "RULES:\n"
    "  • Only design tests you are confident will return discriminating "
    "evidence.\n"
    "  • If a finding cannot be resolved by an HTTP probe, set "
    '"skip": true and explain why.\n'
    "  • For path traversal / file read: expect the target file content "
    "in the body.\n"
    "  • For RCE: use a safe side-channel (sleep=3 timing or DNS lookup).\n"
    "  • For request smuggling: send crafted CL+TE pair and check for "
    "502/garbled response.\n"
    "  • For open redirect: check if Location header matches supplied URL.\n"
    "  • The expected_status should be 200, 403, 500, or 502 — never 404.\n"
    "  • Use the full host context (HTTP response, TLS, headers, tech "
    "stack) to design better tests.\n\n"
    "Respond with a JSON array ONLY — no prose, no markdown fences. Each "
    "element:\n"
    '{"finding_index": <int>, "skip": false,\n'
    ' "method": "GET", "path": "/test",\n'
    ' "headers": {"Header": "value"} or null,\n'
    ' "body": "request body" or null,\n'
    ' "expected_status": [200, 500],\n'
    ' "expected_body_patterns": ["pattern1"],\n'
    ' "tls": false, "port": 80,\n'
    ' "evidence_hint": "what to look for"}\n'
    "If none are resolvable, return []"
)


def build_reprobe_plan(
    potential_items: list[dict],
    host_context: Optional[dict] = None,
    complete: Optional[Callable[[str, str], str]] = None,
) -> list[dict]:
    """Given potential verdict dicts, return probe plans for resolvable ones.

    Each item in *potential_items* should have keys:
      subject, host, port, impact, rationale
    (as emitted by the fusion engine bridge ``_row()``).

    Returns a list of probe plans (same format as verifier planner output)
    that can be executed by ``src.verifier.runner.run_test()``.
    """
    if not potential_items or complete is None:
        return []

    items_json = json.dumps(potential_items, indent=2, default=str)
    parts = ["POTENTIAL FINDINGS:\n```json\n" + items_json + "\n```"]
    if host_context:
        ctx_json = json.dumps(host_context, indent=2, default=str)
        parts.append("HOST CONTEXT:\n```json\n" + ctx_json + "\n```")
    parts.append(
        "For each finding, decide if a probe can resolve it and design "
        "the probe. Return ONE JSON array."
    )
    user = "\n\n".join(parts)

    try:
        text = complete(SYSTEM, user).strip()
        return _parse_probe_plans(text)
    except Exception as exc:
        log.warning("Re-probe plan generation failed (%s) — no re-probes", exc)
        return []


def _parse_probe_plans(text: str) -> list[dict]:
    from src.fusion.ai import robust_json_array
    arr = robust_json_array(text)
    if not isinstance(arr, list):
        log.warning("Re-probe plan parse failed: expected array, got %.100s", text)
        return []
    plans = []
    for obj in arr:
        if not isinstance(obj, dict):
            continue
        if obj.get("skip"):
            continue
        plan = {
            "cve_id": f"reprobe-{obj.get('finding_index', 0)}",
            "method": obj.get("method", "GET"),
            "path": obj.get("path", "/"),
            "expected_status": obj.get("expected_status") or [],
            "expected_body_patterns": obj.get("expected_body_patterns") or [],
            "port": obj.get("port", 80),
            "tls": bool(obj.get("tls", False)),
            "evidence_hint": str(obj.get("evidence_hint", ""))[:200],
        }
        if obj.get("headers"):
            plan["headers"] = obj["headers"]
        if obj.get("body"):
            plan["body"] = obj["body"]
        plans.append(plan)
    return plans
