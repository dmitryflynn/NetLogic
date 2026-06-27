"""Orchestrates the AI planner + runner to produce probe-confirmed signals."""

from __future__ import annotations

import logging
from typing import Callable, Optional

from src.fusion.signals import Signal

log = logging.getLogger("netlogic.verifier.engine")

CompleteFn = Callable[[str, str], str]


def run_verifier(
    host: str,
    port: int,
    service: str,
    product: str,
    version: str,
    cves: list[dict],
    exposure: Optional[dict] = None,
    complete: Optional[CompleteFn] = None,
    cfg=None,
) -> list[Signal]:
    """Run the AI-driven verifier against a single service.

    Returns a list of ``Signal`` objects with ``is_probe_confirmed=True`` for
    every CVE the verifier could actively confirm. These feed into the fusion
    gate as pinned ground truth.
    """
    if not cves:
        return []

    from src.verifier.planner import generate_plans_for_cves
    from src.verifier.runner import run_test

    plans = generate_plans_for_cves(cves, service, product, version, port,
                                    use_tls=(port in (443, 8443)),
                                    complete=complete, cfg=cfg)
    if not plans:
        return []

    use_tls = port in (443, 8443)
    signals: list[Signal] = []

    for plan in plans:
        cve_id = plan.get("cve_id", "unknown")

        result = run_test(plan, host)

        observed = {
            "request_method": plan.get("method", "GET"),
            "request_path": plan.get("path", "/"),
            "response_status": result.status_code,
            "response_snippet": result.response_body[:500] if result.response_body else None,
            "duration_ms": round(result.duration_ms, 1),
            "port": port,
            "service": service,
        }
        if plan.get("headers"):
            observed["request_headers"] = plan.get("headers")

        sig = Signal(
            source="verifier",
            kind="vuln",
            claim=cve_id,
            host=host,
            port=port,
            service=service,
            reliability="high",
            evidence=result.evidence or f"Verification: {plan.get('path', '/')} → {result.status_code}",
            cvss=float(plan.get("cvss_score", 0) or 0),
            epss=float(plan.get("epss", 0) or 0),
            exploit_available=result.success,
            probe_confirmed=result.success,
            version_matched=False,
            observed_data=observed,
            exposure=exposure or {"reachability": "unknown"},
            raw_metadata={"verification_plan": plan, "error": result.error} if result.error else {"verification_plan": plan},
        )
        signals.append(sig)

        log.info("Verifier [%s] %s %s → %s (%s)",
                 cve_id, plan.get("method", "GET"), plan.get("path", "/"),
                 "CONFIRMED" if result.success else "FAILED",
                 result.evidence[:80])

    return signals
