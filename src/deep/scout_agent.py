"""Scout agent — runs passive sensors and returns host context.

The scout collects TLS state, HTTP headers, technology stack, DNS security,
and OSINT data for the target. Its report feeds the coordinator's service-
grouping and probe-prioritisation decisions.
"""

from __future__ import annotations

import logging

from src.deep.models import Mission, AgentReport
from src.deep.base_agent import BaseAgent

log = logging.getLogger("netlogic.deep.scout")


class ScoutAgent(BaseAgent):
    def __init__(self, mission: Mission) -> None:
        super().__init__(mission)

    def execute(self) -> AgentReport:
        target = self.mission.target
        http_port = self.mission.context.get("http_port")
        https_port = self.mission.context.get("https_port")
        args = self.mission.context.get("args", {})
        ports_open = self.mission.context.get("ports_open", [])
        timeout = getattr(args, "timeout", 2.0)

        artifacts: dict = {}

        try:
            if self.mission.context.get("do_tls"):
                from src.tls_analyzer import analyze_tls_ports
                tls_ports = [p.port for p in ports_open if getattr(p, "tls", False) or p.port in (443, 8443, 993, 995, 465)] or [443]
                artifacts["tls_results"] = analyze_tls_ports(target, tls_ports)
        except Exception as e:
            log.warning("Scout TLS: %s", e)

        try:
            if self.mission.context.get("do_headers") and http_port:
                from src.header_audit import audit_headers
                artifacts["header_audit"] = audit_headers(target, https_port or http_port)
        except Exception as e:
            log.warning("Scout headers: %s", e)

        try:
            if self.mission.context.get("do_stack") and http_port:
                from src.stack_fingerprint import fingerprint_stack
                artifacts["stack_result"] = fingerprint_stack(target, https_port or http_port)
        except Exception as e:
            log.warning("Scout stack: %s", e)

        try:
            if self.mission.context.get("do_dns"):
                from src.dns_security import check_dns_security
                artifacts["dns_result"] = check_dns_security(target)
        except Exception as e:
            log.warning("Scout DNS: %s", e)

        try:
            if self.mission.context.get("do_osint"):
                from src.osint import run_osint
                ip = self.mission.context.get("host_ip")
                artifacts["osint_result"] = run_osint(target, ip=ip)
        except Exception as e:
            log.warning("Scout OSINT: %s", e)

        return self._make_report(success=True, artifacts=artifacts)
