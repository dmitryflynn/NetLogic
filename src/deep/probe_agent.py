"""Probe agent — runs active probes for a service group with isolated context.

Each probe agent instance targets one service/port group and receives only
the CVEs and tech context relevant to that service. This prevents cross-
service context contamination in AI-driven probes.
"""

from __future__ import annotations

import logging

from src.deep.models import Mission, AgentReport
from src.deep.base_agent import BaseAgent

log = logging.getLogger("netlogic.deep.probe")


class ProbeAgent(BaseAgent):
    def __init__(self, mission: Mission) -> None:
        super().__init__(mission)

    def execute(self) -> AgentReport:
        target = self.mission.target
        ports_open = self.mission.context.get("ports_open", [])
        timeout = self.mission.context.get("timeout", 2.0)
        signals: list = []
        artifacts: dict = {}

        svc = self.mission.service

        if svc in ("http", "https", "http-alt", "https-alt", "unknown"):
            artifacts.update(self._probe_web(target, ports_open, timeout))

        if self.mission.cves:
            sigs = self._verify_cves(target)
            signals.extend(sigs)
            artifacts["verifier_signals"] = sigs

        return self._make_report(success=True, artifacts=artifacts, signals=signals)

    def _probe_web(self, target: str, ports_open: list, timeout: float) -> dict:
        results: dict = {}
        ctx = self.mission.context or {}
        # Shared probes already run by the coordinator — skip redundant calls
        if not ctx.get("service_probe_result"):
            try:
                from src.service_prober import probe_services
                results["service_probe_result"] = probe_services(target, ports_open, timeout=timeout)
            except Exception as e:
                log.warning("ProbeAgent service_probe: %s", e)
        if not ctx.get("vuln_probe_result"):
            try:
                from src.vuln_prober import probe_web_vulnerabilities
                results["vuln_probe_result"] = probe_web_vulnerabilities(target, ports_open, timeout=timeout)
            except Exception as e:
                log.warning("ProbeAgent vuln_probe: %s", e)
        try:
            http_port = None
            for p in ports_open:
                if p.service in ("http", "https", "http-alt", "https-alt") or getattr(p, "tls", False):
                    http_port = p.port
                    break
            if http_port:
                from src.web_fingerprint import fingerprint_web
                wscheme = "https" if getattr(p, "tls", False) or http_port in (443, 8443) else "http"
                results["web_fingerprint"] = fingerprint_web(target, http_port, wscheme, timeout=max(timeout, 5.0))
        except Exception as e:
            log.warning("ProbeAgent web_fingerprint: %s", e)
        return results

    def _verify_cves(self, target: str) -> list:
        signals: list = []
        ai_complete = self.mission.context.get("ai_complete")
        ai_vcfg = self.mission.context.get("ai_vcfg")
        if not ai_complete or not ai_vcfg:
            return signals
        try:
            from src.verifier.engine import run_verifier
            port = self.mission.port or 0
            service = self.mission.service or ""
            product = self.mission.context.get("product", "")
            version = self.mission.context.get("version", "")
            sigs = run_verifier(
                host=target,
                port=port,
                service=service,
                product=product,
                version=version,
                cves=self.mission.cves,
                complete=ai_complete,
                cfg=ai_vcfg,
            )
            signals.extend(sigs)
        except Exception as e:
            log.warning("ProbeAgent verifier: %s", e)
        return signals
