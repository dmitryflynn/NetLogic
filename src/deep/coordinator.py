"""Deep-probe coordinator — orchestrates the agent-based scan pipeline.

The coordinator:
  1. Builds the sensor plan (AI or default)
  2. Dispatches ScoutAgents for passive recon
  3. Groups findings by service
  4. Dispatches ProbeAgents per service group (with focused context)
  5. Collects and merges agent reports into the art dict
  6. Runs additional modules (topology, auth, diff, reachability)

The coordinator modifies the art dict IN PLACE so the caller
(run_deep_scan) can proceed to fusion + synthesis unchanged.
"""

from __future__ import annotations

import json
import logging
from typing import Callable, Optional

from src.deep.models import Mission
from src.deep.scout_agent import ScoutAgent
from src.deep.probe_agent import ProbeAgent

log = logging.getLogger("netlogic.deep.coordinator")


class DeepCoordinator:
    def __init__(
        self,
        art: dict,
        host_result,
        ports_open: list,
        vuln_matches: list,
        target: str,
        args,
        emit: Optional[Callable],
        ai_complete=None,
        ai_vcfg=None,
    ) -> None:
        self.art = art
        self.host_result = host_result
        self.ports_open = ports_open
        self.vuln_matches = vuln_matches
        self.target = target
        self.args = args
        self._emit_fn = emit
        self.ai_complete = ai_complete
        self.ai_vcfg = ai_vcfg

        self._agent_reports: list = []

    # ── helpers ───────────────────────────────────────────────────────────────

    def _emit(self, etype, data=None, message=None):
        if self._emit_fn is not None:
            self._emit_fn(etype, data, message)
        elif message:
            print(f"[*] {message}")

    def _g(self, name, default=None):
        return getattr(self.args, name, default)

    # ── main entry ────────────────────────────────────────────────────────────

    def run(self) -> dict:
        self._build_sensor_plan()
        self._run_passive_sensors()
        self._run_active_probes()
        self._run_service_enum()
        self._run_nuclei()
        self._run_verifier_agents()
        self._run_takeover()
        self._run_subnet_probe()
        self._run_topology()
        self._run_auth()
        self._run_diff()
        self._run_reachability()
        return self.art

    # ── Sensor plan ───────────────────────────────────────────────────────────

    def _build_sensor_plan(self):
        plan = None
        if self.ai_complete is not None:
            from src.directors.sensor_director import build_sensor_plan
            try:
                port_dicts = []
                for p in self.ports_open:
                    b = getattr(p, "banner", None)
                    if b is not None and not isinstance(b, str):
                        b = getattr(b, "raw", str(b))
                    port_dicts.append({
                        "port": p.port,
                        "service": getattr(p, "service", ""),
                        "banner": (b or "")[:200],
                    })
                plan = build_sensor_plan(
                    open_ports=port_dicts,
                    vuln_matches=self.vuln_matches,
                    complete=self.ai_complete,
                )
            except Exception as exc:
                self._emit("log", {"text": f"SensorDirector: {exc}", "level": "warn"})

        # Handle --sensor-plan override
        override = self._g("sensor_plan", "")
        if override and plan is not None:
            if override == "show":
                self._emit("log", {"text": f"Sensor plan:\n{json.dumps(plan, indent=2)}",
                                  "level": "info"})
            else:
                try:
                    ov = json.loads(override)
                    if isinstance(ov, dict):
                        from src.directors.sensor_director import ALL_SENSORS
                        for name, cfg in ov.items():
                            if name in ALL_SENSORS and isinstance(cfg, dict):
                                existing = plan.get(name, {})
                                existing.update(cfg)
                                plan[name] = existing
                        self._emit("log", {"text": "Sensor plan overridden via --sensor-plan",
                                          "level": "info"})
                except json.JSONDecodeError:
                    self._emit("log", {"text": f"Invalid --sensor-plan JSON: {override}",
                                      "level": "warn"})

        self._sensor_plan = plan

    def _sensor_enabled(self, name: str, default: bool = True) -> bool:
        if self._sensor_plan is None:
            return default
        cfg = self._sensor_plan.get(name, {})
        if isinstance(cfg, dict):
            return bool(cfg.get("enabled", default))
        return default

    # ── Passive sensors ───────────────────────────────────────────────────────

    def _run_passive_sensors(self):
        ai_deep = self._g("ai", False)
        full = self._g("full", False)

        do_tls = self._g("tls", False) or full or ai_deep
        do_headers = self._g("headers", False) or full or ai_deep
        do_stack = self._g("stack", False) or full or ai_deep
        do_dns = self._g("dns", False) or full or ai_deep
        do_osint = self._g("osint", False) or full or ai_deep

        if not any([do_tls, do_headers, do_stack, do_dns, do_osint]):
            return

        http_port = next((p.port for p in self.ports_open
                          if p.service in ("http", "https", "http-alt", "https-alt")), None)
        https_port = next((p.port for p in self.ports_open
                           if getattr(p, "tls", False) or p.port in (443, 8443)
                           or p.service in ("https", "https-alt")), None)

        mission = Mission(
            agent_type="scout",
            target=self.target,
            context={
                "do_tls": do_tls,
                "do_headers": do_headers,
                "do_stack": do_stack,
                "do_dns": do_dns,
                "do_osint": do_osint,
                "http_port": http_port,
                "https_port": https_port,
                "ports_open": self.ports_open,
                "host_ip": getattr(self.host_result, "ip", None),
                "args": self.args,
            },
        )
        agent = ScoutAgent(mission)
        self._emit("progress", {"percent": 78, "status": "Deep-probe: passive recon…"},
                   message="Deep-probe: running passive sensors through scout agent…")
        report = agent.execute()
        self._agent_reports.append(report)

        for key in ("tls_results", "header_audit", "stack_result", "dns_result", "osint_result"):
            if key in report.artifacts:
                self.art[key] = report.artifacts[key]

    # ── Active probes ─────────────────────────────────────────────────────────

    def _run_active_probes(self):
        do_probe = self._g("probe", False) or self._g("full", False)
        if not self._sensor_enabled("probes", do_probe) or not self.ports_open:
            return

        # Run shared probes once instead of once per port
        if not self.art.get("service_probe_result"):
            try:
                from src.service_prober import probe_services
                self.art["service_probe_result"] = probe_services(
                    self.target, self.ports_open, timeout=self._g("timeout", 2.0),
                )
            except Exception as e:
                log.warning("probe_services: %s", e)
        if not self.art.get("vuln_probe_result"):
            try:
                from src.vuln_prober import probe_web_vulnerabilities
                self.art["vuln_probe_result"] = probe_web_vulnerabilities(
                    self.target, self.ports_open, timeout=self._g("timeout", 2.0),
                )
            except Exception as e:
                log.warning("probe_web_vulnerabilities: %s", e)

        # Tell ProbeAgents the shared probes are already done
        _shared_done = {
            "service_probe_result": self.art.get("service_probe_result"),
            "vuln_probe_result": self.art.get("vuln_probe_result"),
        }

        ai_complete = self.ai_complete
        ai_vcfg = self.ai_vcfg

        self._emit("progress", {"percent": 85, "status": "Deep-probe: active probes…"},
                   message="Deep-probe: dispatching per-service probe agents…")

        for p in self.ports_open:
            svc = p.service or "unknown"
            cves_for_port = []
            product = ""
            version = ""
            for vm in self.vuln_matches:
                if getattr(vm, "port", 0) == p.port:
                    product = getattr(vm, "product", "") or ""
                    version = getattr(vm, "version", "") or ""
                    for c in getattr(vm, "cves", []) or []:
                        cves_for_port.append({
                            "id": c.id,
                            "description": getattr(c, "description", ""),
                            "cvss_score": getattr(c, "cvss_score", 0.0),
                            "severity": getattr(c, "severity", ""),
                            "epss": getattr(c, "epss", 0.0),
                            "exploit_available": getattr(c, "exploit_available", False),
                            "references": getattr(c, "references", []),
                        })

            mission = Mission(
                agent_type="probe",
                target=self.target,
                service=svc,
                port=p.port,
                cves=cves_for_port,
                context={
                    "ports_open": self.ports_open,
                    "timeout": self._g("timeout", 2.0),
                    "product": product,
                    "version": version,
                    "ai_complete": ai_complete,
                    "ai_vcfg": ai_vcfg,
                    **_shared_done,
                },
            )
            agent = ProbeAgent(mission)
            report = agent.execute()
            self._agent_reports.append(report)

            if "web_fingerprint" in report.artifacts and not self.art.get("web_fingerprint"):
                self.art["web_fingerprint"] = report.artifacts["web_fingerprint"]

    # ── Service enumeration ───────────────────────────────────────────────────

    def _run_service_enum(self):
        ai_deep = self._g("ai", False)
        full = self._g("full", False)
        if not self._sensor_enabled("service_enum", (ai_deep or full)) or not self.ports_open:
            return
        self._emit("progress", {"percent": 92, "status": "Service exploitability…"},
                   message="Deep-probe: enumerating service exploitability…")
        try:
            from src.service_enum import enumerate_services
            self.art["service_enum_result"] = enumerate_services(
                self.target, self.ports_open, timeout=self._g("timeout", 2.0)
            )
        except Exception as e:
            self._emit("log", {"text": f"Service enum: {e}", "level": "warn"})

    # ── Nuclei ────────────────────────────────────────────────────────────────

    def _run_nuclei(self):
        ai_deep = self._g("ai", False)
        full = self._g("full", False)
        if not self._sensor_enabled("nuclei", (ai_deep or full)):
            return
        try:
            from src.external.nuclei_runner import scan as nuclei_scan, available as nuclei_available
            from src.directors.nuclei_selector import select_nuclei_tags
        except ImportError:
            return

        tech_list = []
        stack_result = self.art.get("stack_result") or {}
        if isinstance(stack_result, dict):
            for t in (stack_result.get("technologies", []) or []):
                if isinstance(t, dict):
                    tech_list.append(t)

        tags = select_nuclei_tags(
            open_ports=[{"port": p.port, "service": getattr(p, "service", "")} for p in self.ports_open],
            tech_stack=tech_list,
            vuln_matches=self.vuln_matches,
            complete=self.ai_complete,
        )

        https_port = next((p.port for p in self.ports_open
                           if getattr(p, "tls", False) or p.port in (443, 8443)
                           or p.service in ("https", "https-alt")), None)
        http_port = next((p.port for p in self.ports_open
                          if p.service in ("http", "https", "http-alt", "https-alt")), None)
        web_port = https_port or http_port

        self._emit("progress", {"percent": 93, "status": "Nuclei deep-scan…"},
                   message=f"Nuclei: {','.join(tags)}…")
        try:
            if nuclei_available():
                target_url = f"https://{self.target}" if https_port else f"http://{self.target}"
                self.art["nuclei_results"] = nuclei_scan(
                    target_url,
                    tags=",".join(tags),
                    timeout=min(int(self._g("timeout", 2.0)) * 3, 120),
                )
        except Exception as e:
            self._emit("log", {"text": f"Nuclei scan: {e}", "level": "warn"})

    # ── Verifier phase 2 ──────────────────────────────────────────────────────

    def _run_verifier_agents(self):
        phase1_sigs = self.art.get("verifier_signals") or []
        if not phase1_sigs or self.ai_complete is None:
            return
        from src.fusion.engine_bridge import build_engine_context
        from src.verifier.planner import reverify_with_context
        from src.verifier.runner import run_test as run_verifier_test
        from src.fusion.signals import Signal

        self._emit("progress", {"percent": 94, "status": "Verifier Phase 2…"},
                   message="Deep-probe: re-verifying with enriched context…")
        try:
            ctx = build_engine_context(self.art)
            failed_cves = set()
            for s in phase1_sigs:
                if not s.probe_confirmed and s.claim.startswith("CVE-"):
                    failed_cves.add(s.claim)

            if not failed_cves:
                return

            plans = reverify_with_context(
                cve_ids=list(failed_cves),
                phase1_results=[],
                context=ctx,
                complete=self.ai_complete,
            )
            new_sigs = []
            host_ip = getattr(self.host_result, "ip", None) or self.target
            for plan in plans:
                port2 = plan.get("port", 443)
                result = run_verifier_test(plan, host=host_ip)
                new_sigs.append(Signal(
                    source="verifier", kind="vuln",
                    claim=plan.get("cve_id", "unknown"),
                    host=host_ip, port=port2,
                    reliability="high",
                    evidence=result.evidence or f"Phase 2: {plan.get('path', '/')} → {result.status_code}",
                    exploit_available=result.success,
                    probe_confirmed=result.success,
                    observed_data={"reason": "reverify", "plan": plan, "status": result.status_code},
                    exposure={"reachability": "public"},
                ))
            if new_sigs:
                self.art["verifier_signals"] = (phase1_sigs or []) + new_sigs
                self._emit("log", {"text": f"Verifier Phase 2: {len(new_sigs)} new probe results",
                                  "level": "info"})
        except Exception as exc:
            self._emit("log", {"text": f"Verifier Phase 2: {exc}", "level": "warn"})

    # ── Subdomain takeover ────────────────────────────────────────────────────

    def _run_takeover(self):
        do_takeover = self._g("takeover", False) or self._g("full", False) or self._g("ai", False)
        if not self._sensor_enabled("takeover", do_takeover):
            return
        from src.takeover import discover_and_check
        self._emit("progress", {"percent": 92, "status": "Subdomain takeover…"},
                   message="Checking subdomains for takeover…")
        try:
            self.art["takeover_result"] = discover_and_check(self.target)
        except Exception as e:
            self._emit("log", {"text": f"Takeover: {e}", "level": "warn"})

    # ── Subnet probe ──────────────────────────────────────────────────────────

    def _run_subnet_probe(self):
        do_probe = self._g("probe", False) or self._g("full", False)
        if not self._sensor_enabled("subnet_probe", do_probe):
            return
        target_ip = getattr(self.host_result, "ip", None) or self.target
        from src.network_prober import probe_subnet, probe_targets
        from src.directors.subnet_director import build_subnet_directive

        directive = None
        if self.ai_complete is not None:
            port_dicts = []
            for p in self.ports_open:
                b = getattr(p, "banner", None)
                if b is not None and not isinstance(b, str):
                    b = getattr(b, "raw", str(b))
                port_dicts.append({
                    "port": p.port,
                    "service": getattr(p, "service", ""),
                    "banner": (b or "")[:200],
                })
            try:
                directive = build_subnet_directive(
                    target_ip=target_ip, open_ports=port_dicts,
                    vuln_matches=self.vuln_matches, complete=self.ai_complete,
                )
            except Exception as exc:
                self._emit("log", {"text": f"Subnet director: {exc}", "level": "warn"})

        action = (directive or {}).get("action", "standard")
        self._emit("progress", {"percent": 93, "status": "Subnet probe…"},
                   message=f"Probing adjacent hosts ({action})…")
        probed_hosts = []
        try:
            if action == "skip":
                self._emit("log", {"text": f"Subnet probe skipped: {((directive or {}).get('reason', ''))[:120]}",
                                  "level": "info"})
            elif action in ("deep", "standard", "quick"):
                ai_targets = (directive or {}).get("targets") or []
                ai_ports = (directive or {}).get("ports_per_target") or {}
                if ai_targets and ai_ports:
                    all_ports = list(set(sum(ai_ports.values(), [])))
                    if all_ports:
                        found = probe_targets(ai_targets, all_ports,
                                              timeout=min(self._g("timeout", 2.0), 2.0),
                                              max_workers=self._g("threads", 100))
                        probed_hosts = [(h.ip, h.port) for h in found]
                        self._emit("log", {"text": f"Subnet probe: {len(found)} open ports on "
                                                  f"{len(set(h.ip for h in found))} AI-selected hosts",
                                          "level": "info"})
                else:
                    sr = probe_subnet(target_ip, timeout=min(self._g("timeout", 2.0), 2.0),
                                      max_workers=self._g("threads", 100))
                    if sr.hosts:
                        probed_hosts = [(h.ip, h.port) for h in sr.hosts]
                        self._emit("log", {"text": f"Subnet probe: {sr.live_host_count} live hosts, "
                                                  f"{len(sr.hosts)} open ports ({sr.scan_duration_s:.1f}s)",
                                          "level": "info"})
                    elif sr.live_host_count > 0:
                        self._emit("log", {"text": f"Subnet probe: {sr.live_host_count} live hosts, "
                                                  f"no common ports open",
                                          "level": "info"})
        except Exception as e:
            self._emit("log", {"text": f"Subnet probe: {e}", "level": "warn"})
        self.art["probed_hosts"] = probed_hosts

    # ── Topology ──────────────────────────────────────────────────────────────

    def _run_topology(self):
        ai_deep = self._g("ai", False)
        full = self._g("full", False)
        if not (ai_deep or full):
            return
        from src.topology import map_topology
        self._emit("progress", {"percent": 96, "status": "Network topology…"},
                   message="Mapping network topology…")
        try:
            self.art["topology"] = map_topology(
                self.target, self.host_result.ip,
                do_traceroute=not self._g("no_traceroute", False),
                timeout=self._g("timeout", 2.0),
            )
        except Exception as e:
            self._emit("log", {"text": f"Topology: {e}", "level": "warn"})

    # ── Authenticated scan ────────────────────────────────────────────────────

    def _run_auth(self):
        ssh_user = self._g("ssh_user", "")
        if not ssh_user:
            return
        from src.authenticated import ssh_enumerate
        self._emit("progress", {"percent": 98, "status": "Authenticated SSH enum…"},
                   message=f"Authenticated scan: {ssh_user}@{self.target}…")
        try:
            self.art["auth_result"] = ssh_enumerate(
                self.target, ssh_user,
                key_path=self._g("ssh_key") or None,
                password=self._g("ssh_pass") or None,
                port=self._g("ssh_port", 22),
            )
        except Exception as e:
            self._emit("log", {"text": f"Authenticated scan: {e}", "level": "warn"})

    # ── Change diff ───────────────────────────────────────────────────────────

    def _run_diff(self):
        if self._g("no_diff", False):
            return
        from src.scan_diff import diff_against_last
        try:
            self.art["scan_diff"] = diff_against_last(
                self.host_result, self.vuln_matches,
                self._g("out", "."), self.target,
            )
        except Exception as e:
            self._emit("log", {"text": f"Scan diff: {e}", "level": "warn"})

    # ── Reachability ──────────────────────────────────────────────────────────

    def _run_reachability(self):
        try:
            from src.reachability_prober import hosts_ports_from_artifacts, build_reachability
            pairs = hosts_ports_from_artifacts(self.art)
            self.art["reachability"] = build_reachability(pairs)
        except Exception as e:
            self._emit("log", {"text": f"Reachability probe: {e}", "level": "warn"})
            self.art["reachability"] = {}
