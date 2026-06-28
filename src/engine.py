"""
NetLogic - Scan Engine (single source of truth)
===============================================
ONE scan implementation, used by both the CLI (netlogic.py) and the GUI/API
streaming bridge (json_bridge.py). Previously these were two divergent code paths,
so features added to the CLI never reached the GUI. Now both call run_scan():

  • CLI  → run_scan(emit=None): prints "[*]" progress, then renders the report.
  • GUI  → run_scan(emit=cb):   every stage is streamed as a structured event.

run_scan gathers everything (scan, CVE correlation + EPSS, TLS, headers, stack,
DNS, OSINT, takeover, active probes, service exploitability, web fingerprint,
topology, authenticated SSH enum, change-diff, AI analysis) and returns an
artifacts dict. build_json_report() turns artifacts into the saved JSON report.
"""
from __future__ import annotations

import json
from dataclasses import asdict

from src.scanner import scan_host
from src.cve_correlator import correlate
from src.osint import run_osint


def _g(args, name, default=None):
    return getattr(args, name, default)


def run_scan(target: str, ports: list, args, emit=None) -> dict:
    """Run a full scan and return an artifacts dict. Streams events via emit if given.

    emit(event_type: str, data: dict | None, message: str | None)
    """
    def _emit(etype, data=None, message=None):
        if emit is not None:
            emit(etype, data, message)
        elif message:                      # CLI: human progress only
            print(f"[*] {message}")

    streaming = emit is not None
    timeout = _g(args, "timeout", 2.0)
    threads = _g(args, "threads", 100)
    min_cvss = _g(args, "min_cvss", 4.0)
    full = _g(args, "full", False)
    ai_deep = _g(args, "ai", False)

    # Which deep modules to run. --ai implies the rich passive set; --full = all.
    do_tls      = _g(args, "tls", False)      or full or ai_deep
    do_headers  = _g(args, "headers", False)  or full or ai_deep
    do_takeover = _g(args, "takeover", False) or full or ai_deep
    do_osint    = _g(args, "osint", False)    or full or ai_deep
    do_stack    = _g(args, "stack", False)    or full or ai_deep
    do_dns      = _g(args, "dns", False)      or full or ai_deep
    do_probe    = _g(args, "probe", False)    or full
    # Fusion adjudication (sensors→gate→AI precision funnel). Opt-in; runs when --ai
    # is on (it uses the AI to judge the gray band) or when explicitly requested.
    do_fusion   = _g(args, "fusion", False)   or ai_deep

    # ── Port scan (streams ports live when emitting) ──
    _emit("progress", {"percent": 10, "status": f"Scanning {target} ({len(ports)} ports)…"},
          message=f"Scanning {target} ({len(ports)} ports)…")

    def _on_port(pr):
        _emit("port", {"target": target, **asdict(pr)})

    host_result = scan_host(target, ports=ports, max_workers=threads, timeout=timeout,
                            on_open_port=_on_port if streaming else None)
    _emit("host", {
        "target": host_result.target, "ip": host_result.ip, "hostname": host_result.hostname,
        "os_guess": host_result.os_guess, "ttl": host_result.ttl,
        "timestamp": host_result.timestamp, "scan_duration_s": host_result.scan_duration_s,
    })

    # ── CVE correlation (+ EPSS, done inside correlate) ──
    from src.nvd_lookup import cache_stats
    n = cache_stats().get("entries", 0)
    _emit("progress", {"percent": 60, "status": "Correlating CVEs…"},
          message=f"Correlating CVEs via NVD API ({'cache: %d entries' % n if n else 'live queries'})…")
    vuln_matches = correlate(host_result.ports, min_cvss=min_cvss, verbose=not streaming)
    for vm in vuln_matches:
        _emit("vuln", {"target": host_result.ip, **_vuln_to_dict(vm)})

    art: dict = {
        "host_result": host_result, "vuln_matches": vuln_matches,
        "tls_results": [], "header_audit": None, "stack_result": None, "dns_result": None,
        "takeover_result": None, "osint_result": None, "service_probe_result": None,
        "vuln_probe_result": None, "service_enum_result": None, "web_fingerprint": None,
        "topology": None, "auth_result": None, "scan_diff": None, "ai_analysis": None,
        "fusion": None, "nuclei_results": None, "reachability": None,
        "verifier_signals": None,
    }
    ports_open = host_result.ports

    http_port = next((p.port for p in ports_open
                      if p.service in ("http", "https", "http-alt", "https-alt")), None)
    # Prefer a TLS/HTTPS port for the header & stack audits — HSTS and most
    # security headers are only meaningful over HTTPS, so auditing the plain-HTTP
    # port first (80 sorts before 443) would understate the real posture.
    https_port = next((p.port for p in ports_open
                       if getattr(p, "tls", False) or p.port in (443, 8443)
                       or p.service in ("https", "https-alt")), None)
    web_port = https_port or http_port or 443

    # ── Cross-step mutable state ──
    _probed_hosts: list[tuple[str, int]] = []

    # ── Sensor registry ──
    # Each SensorStep wraps one inline stage with a `run` closure capturing the engine
    # scope. Passive steps run before AI config; the rest are dispatched by the adaptive
    # loop (if triggered) or iterated in order (default).
    from src.reasoning.registry import SensorStep  # noqa: PLC0415

    REGISTRY: list[SensorStep] = []

    # TLS
    if True:
        from src.tls_analyzer import analyze_tls_ports  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="tls", persona="technology_fingerprinting", is_passive=True,
            applies=lambda ctx: do_tls,
            run=lambda ctx: _run_tls(ctx, target, ports_open),
            base_gain=1.0,
        ))

    # HTTP headers
    if True:
        from src.header_audit import audit_headers  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="headers", persona="technology_fingerprinting", is_passive=True,
            applies=lambda ctx: do_headers,
            run=lambda ctx: _run_headers(ctx, target, web_port, audit_headers),
            base_gain=1.0,
        ))

    # Tech stack
    if True:
        from src.stack_fingerprint import fingerprint_stack  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="stack", persona="technology_fingerprinting", is_passive=True,
            applies=lambda ctx: do_stack,
            run=lambda ctx: _run_stack(ctx, target, web_port, fingerprint_stack),
            base_gain=1.0,
        ))

    # DNS/email
    if True:
        from src.dns_security import check_dns_security  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="dns", persona="service_discovery", is_passive=True,
            applies=lambda ctx: do_dns,
            run=lambda ctx: _run_dns(ctx, target, check_dns_security),
            base_gain=0.8,
        ))

    # OSINT
    if True:
        REGISTRY.append(SensorStep(
            name="osint", persona="service_discovery", is_passive=True,
            applies=lambda ctx: do_osint,
            run=lambda ctx: _run_osint(ctx, target, host_result),
            base_gain=1.2,
        ))

    # CVE verification (AI-driven)
    if True:
        from src.verifier.engine import run_verifier  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="cve_verifier", persona="cve_verification",
            applies=lambda ctx: (ai_deep or full) and vuln_matches
                                and ctx.completer is not None,
            run=lambda ctx: _run_cve_verifier(ctx, host_result, vuln_matches,
                                              target, run_verifier),
            base_gain=2.0, resolves=("version_only", "cve"),
            cost={"time_ms": 8000, "tokens": 6000, "probes": 5},
        ))

    # Subdomain takeover
    if True:
        from src.takeover import discover_and_check  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="takeover", persona="application_mapping",
            applies=lambda ctx: _sensor_applies(ctx, "takeover", do_takeover),
            run=lambda ctx: _run_takeover(ctx, target, discover_and_check),
            base_gain=1.5,
        ))

    # Active probes (service + vuln)
    if True:
        from src.service_prober import probe_services  # noqa: PLC0415
        from src.vuln_prober import probe_web_vulnerabilities  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="probes", persona="application_mapping",
            applies=lambda ctx: _sensor_applies(ctx, "probes", do_probe) and ports_open,
            run=lambda ctx: _run_probes(ctx, target, ports_open, timeout,
                                        probe_services, probe_web_vulnerabilities),
            base_gain=1.0,
        ))

    # AI-directed subnet probe
    if True:
        from src.network_prober import probe_subnet, probe_targets  # noqa: PLC0415
        from src.directors.subnet_director import build_subnet_directive  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="subnet_probe", persona="service_discovery",
            applies=lambda ctx: _sensor_applies(ctx, "subnet_probe", do_probe),
            run=lambda ctx: _run_subnet(ctx, host_result, vuln_matches, ports_open,
                                        target, timeout, threads,
                                        probe_subnet, probe_targets,
                                        build_subnet_directive, _probed_hosts),
            base_gain=1.5,
        ))

    # Service exploitability enumeration
    if True:
        from src.service_enum import enumerate_services  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="service_enum", persona="application_mapping",
            applies=lambda ctx: _sensor_applies(ctx, "service_enum", (ai_deep or full))
                                and ports_open,
            run=lambda ctx: _run_service_enum(ctx, target, ports_open, timeout,
                                              enumerate_services),
            base_gain=1.0,
        ))

    # Web fingerprint
    if True:
        from src.web_fingerprint import fingerprint_web  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="web_fingerprint", persona="application_mapping",
            applies=lambda ctx: _sensor_applies(ctx, "web_fingerprint", (ai_deep or full))
                                and http_port is not None,
            run=lambda ctx: _run_web_fingerprint(ctx, target, http_port, ports_open,
                                                 timeout, fingerprint_web),
            base_gain=1.2,
        ))

    # Nuclei external scan
    if True:
        from src.external.nuclei_runner import scan as nuclei_scan  # noqa: PLC0415
        from src.external.nuclei_runner import available as nuclei_available  # noqa: PLC0415
        from src.directors.nuclei_selector import select_nuclei_tags  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="nuclei", persona="cve_verification",
            applies=lambda ctx: _sensor_applies(ctx, "nuclei", (ai_deep or full)),
            run=lambda ctx: _run_nuclei(ctx, target, ports_open, https_port,
                                        timeout, select_nuclei_tags,
                                        nuclei_available, nuclei_scan),
            base_gain=1.8, resolves=("cve",),
            cost={"time_ms": 30000, "tokens": 2000, "probes": 0},
        ))

    # Verifier Phase 2 (reverify with full context)
    if True:
        from src.fusion.engine_bridge import build_engine_context  # noqa: PLC0415
        from src.verifier.planner import reverify_with_context  # noqa: PLC0415
        from src.verifier.runner import run_test as run_verifier_test  # noqa: PLC0415
        from src.fusion.signals import Signal  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="verifier2", persona="cve_verification",
            applies=lambda ctx: ctx.art.get("verifier_signals")
                                and ctx.completer is not None,
            run=lambda ctx: _run_verifier2(ctx, host_result, target,
                                           build_engine_context,
                                           reverify_with_context,
                                           run_verifier_test, Signal),
            base_gain=1.5, resolves=("cve",),
            cost={"time_ms": 12000, "tokens": 4000, "probes": 3},
        ))

    # Topology
    if True:
        from src.topology import map_topology  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="topology", persona="service_discovery",
            applies=lambda ctx: ai_deep or full,
            run=lambda ctx: _run_topology(ctx, target, host_result, args, timeout,
                                          map_topology),
            base_gain=0.8,
        ))

    # Authenticated SSH scan
    if True:
        from src.authenticated import ssh_enumerate  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="auth_ssh", persona="pivot_discovery",
            applies=lambda ctx: _g(ctx.args or args, "ssh_user", ""),
            run=lambda ctx: _run_auth_ssh(ctx, target, args, ssh_enumerate),
            base_gain=1.0,
        ))

    # Change diff
    if True:
        from src.scan_diff import diff_against_last  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="diff", persona="service_discovery",
            applies=lambda ctx: not _g(ctx.args or args, "no_diff", False),
            run=lambda ctx: _run_diff(ctx, host_result, vuln_matches, target,
                                      args, diff_against_last),
            base_gain=0.5,
        ))

    # Reachability probe
    if True:
        from src.reachability_prober import hosts_ports_from_artifacts  # noqa: PLC0415
        from src.reachability_prober import build_reachability  # noqa: PLC0415
        REGISTRY.append(SensorStep(
            name="reachability", persona="service_discovery",
            applies=lambda ctx: True,
            run=lambda ctx: _run_reachability(ctx, _probed_hosts,
                                              hosts_ports_from_artifacts,
                                              build_reachability),
            base_gain=0.6,
        ))

    # ── PASS 1: passive sweep (no AI needed) ──
    from src.reasoning import ReasoningState, StepContext  # noqa: PLC0415
    _passive_ctx = StepContext(target=target, state=ReasoningState(), art=art, emit=_emit, args=args)
    for _step in REGISTRY:
        if _step.is_passive and _step.applies(_passive_ctx):
            _step.run(_passive_ctx)

    # ── Shared AI config (used by all AI-driven modules below) ──
    _ai_complete = None
    _ai_vcfg = None
    if ai_deep or full:
        from src import ai_analyst  # noqa: PLC0415
        from src.fusion.ai import make_completer  # noqa: PLC0415
        _ai_vcfg = ai_analyst.config_for_org(_g(args, "org_id", ""), role="ai")
        for attr, key in (("api_key", "ai_key"), ("provider", "ai_provider"),
                          ("model", "ai_model"), ("base_url", "ai_base_url")):
            val = _g(args, key)
            if val:
                setattr(_ai_vcfg, attr, val)
        _ai_vcfg.resolve()
        try:
            usable, _ = _ai_vcfg.is_usable()
            if usable:
                _ai_complete = make_completer(_ai_vcfg)
        except Exception:  # noqa: BLE001
            pass

    # ── SensorDirector: AI decides which sensors to prioritise ──
    _sensor_plan = None
    if _ai_complete is not None:
        from src.directors.sensor_director import build_sensor_plan  # noqa: PLC0415
        try:
            _port_dicts = [
                {"port": p.port, "service": getattr(p, "service", ""),
                 "banner": getattr(getattr(p, "banner", None), "raw", "") or ""}
                for p in ports_open
            ]
            _sensor_plan = build_sensor_plan(
                open_ports=_port_dicts,
                vuln_matches=vuln_matches,
                complete=_ai_complete,
            )
        except Exception as exc:  # noqa: BLE001
            _emit("log", {"text": f"SensorDirector: {exc}", "level": "warn"})

    # ── Build initial StepContext ──
    _ctx = StepContext(target=target, state=None, art=art, emit=_emit, args=args)

    # ── Build initial ReasoningState (from pass 1 data) ──
    from src.reasoning.builder import refresh_beliefs, safe_build_reasoning_state  # noqa: PLC0415
    _rs = safe_build_reasoning_state(target, [target], art)

    # ── ADAPTIVE LOOP (opt-in via --reason) OR DEFAULT PASS ──
    # Activation is governed by reasoning_enabled, NOT the AI key: with --reason off the
    # director never runs and the non-passive sensors execute in default order (byte-
    # identical). With --reason on, the deterministic loop runs; AI (if present) augments.
    _ran_director = False
    if _rs is not None:
        _rs.reasoning_enabled = bool(_g(args, "reason", False))
        # Multi-host world modeling (Phase 6c) is gated independently and implies --reason.
        _rs.world_modeling_enabled = bool(_g(args, "multi_host", False)) and _rs.reasoning_enabled
    _ctx.state = _rs
    _ctx.completer = _ai_complete
    _ctx.extras["sensor_plan"] = _sensor_plan
    _ctx.extras["ai_vcfg"] = _ai_vcfg

    from src.reasoning import BudgetManager, ReconDirector, Scheduler, StrategyManager  # noqa: PLC0415
    _strategy = StrategyManager()
    _budget = BudgetManager.for_tier("hosted" if streaming else "local")
    if _rs is not None and _strategy.should_activate(
            _rs, has_ai_key=(_ai_complete is not None), budget=_budget):
        def _persist(st):
            from api.storage.reasoning_store import reasoning_store  # noqa: PLC0415
            jid = _g(args, "job_id", "") or ""
            if jid:
                reasoning_store.persist(jid, _g(args, "org_id", "") or "", target, st.to_dict())

        ReconDirector(Scheduler(), _strategy, _budget, REGISTRY,
                      has_ai_key=(_ai_complete is not None), ai_completer=_ai_complete,
                      refresh=lambda st, a: refresh_beliefs(st, a),
                      persist=_persist).run(_ctx)
        _rs = _ctx.state
        _ran_director = True
    else:
        for _step in REGISTRY:
            if not _step.is_passive and _step.applies(_ctx):
                _step.run(_ctx)

    # ── Fusion pipeline (sensors → gate → AI adjudication → unified analysis) ──
    # The fusion pipeline OWNS the full AI analysis. When fusion produces an
    # `ai_analysis` key, it replaces the separate ai_analyst.analyze_scan() call.
    # If fusion runs but does NOT produce AI analysis (no AI configured, synthesis
    # error), we fall back to the legacy ai_analyst.
    fusion_produced_ai = False
    if do_fusion:
        _emit("progress", {"percent": 97, "status": "Resolving signals…"},
              message="Fusion: building signals from artifacts…")
        try:
            from src.fusion.engine_bridge import run_fusion
            _emit("progress", {"percent": 98, "status": "Gate + AI adjudication…"},
                  message="Fusion: running gate + AI adjudication…")
            # Streaming callback — emit progressive "ai" events as tokens arrive
            _ai_md_chunks: list[str] = []
            _ai_md_len = 0
            _ai_md_emit_len = 0

            def _on_ai_token(token: str):
                nonlocal _ai_md_chunks, _ai_md_len, _ai_md_emit_len
                _ai_md_chunks.append(token)
                _ai_md_len += len(token)
                # Emit every ~80 chars so the front end shows incremental output
                if _ai_md_len - _ai_md_emit_len >= 80:
                    _emit("ai", {"markdown": "".join(_ai_md_chunks)})
                    _ai_md_emit_len = _ai_md_len

            art["fusion"] = run_fusion(art, cfg=_ai_vcfg, on_token=_on_ai_token)
            _emit("progress", {"percent": 99, "status": "Unified analysis…"},
                  message="Fusion: synthesizing unified analysis…")
            _emit("fusion", art["fusion"])
            if art["fusion"] and art["fusion"].get("ai_analysis"):
                art["ai_analysis"] = _fusion_ai_as_analysis(art["fusion"])
                fusion_produced_ai = True
                # Include beyond_cves in the SSE event alongside the markdown
                bc = art["fusion"].get("beyond_cves", [])
                ai_evt = {
                    "markdown": art["ai_analysis"].markdown,
                    "error": art["ai_analysis"].error,
                    "provider": art["ai_analysis"].provider,
                    "model": art["ai_analysis"].model,
                }
                if bc:
                    ai_evt["beyond_cves"] = bc
                _emit("ai", ai_evt)
        except Exception as e:
            _emit("log", {"text": f"Fusion: {e}", "level": "warn"})

    # ── Iterative re-probe loop: resolve potential findings via targeted probes ──
    # After fusion pass 1, items with decision='potential' remain. The AI decides
    # which can be resolved by a targeted probe, we execute them, and run a mini
    # re-adjudication (gate only, no full AI re-adjudication). Max one iteration.
    if art.get("fusion") and _ai_complete is not None:
        _potential_items = art["fusion"].get("potential", [])
        if _potential_items:
            from src.directors.reprobe import build_reprobe_plan  # noqa: PLC0415
            from src.verifier.runner import run_test as _reprobe_executor  # noqa: PLC0415
            from src.fusion.signals import Signal  # noqa: PLC0415
            from src.fusion.gate import adjudicate  # noqa: PLC0415

            _emit("progress", {"percent": 99, "status": "Re-probing potential items…"},
                  message="Fusion: re-probing potential findings…")
            try:
                _reprobe_plans = build_reprobe_plan(
                    _potential_items,
                    host_context=build_engine_context(art),
                    complete=_ai_complete,
                )
                if _reprobe_plans:
                    _reprobe_signals: list = []
                    for _plan in _reprobe_plans:
                        _p_port = _plan.get("port", 443)
                        _result = _reprobe_executor(_plan, host=host_result.ip or target)
                        _reprobe_signals.append(Signal(
                            source="verifier", kind="vuln",
                            claim=_plan.get("cve_id", "reprobe"),
                            host=host_result.ip or target, port=_p_port,
                            reliability="high",
                            evidence=_result.evidence or f"Re-probe: {_plan.get('path', '/')} → {_result.status_code}",
                            exploit_available=_result.success,
                            probe_confirmed=_result.success,
                            observed_data={"reason": "reprobe", "plan": _plan, "status": _result.status_code},
                            exposure={"reachability": "public"},
                        ))
                    if _reprobe_signals:
                        # Mini re-adjudication: gate only on new signals
                        _mini_verdicts = adjudicate(_reprobe_signals)
                        _new_confirmed = [v for v in _mini_verdicts if v.decision == "confirmed"]
                        if _new_confirmed:
                            for _nv in _new_confirmed:
                                art["fusion"]["confirmed"].insert(0, {
                                    "subject": _nv.claim, "port": _nv.port,
                                    "decision": "confirmed", "impact": _nv.impact,
                                    "pinned": True, "agreement": 1,
                                    "rationale": "re-probe confirmed",
                                    "ai": None, "safety_override": False,
                                })
                            _emit("log", {"text": f"Re-probe: {len(_new_confirmed)} items resolved",
                                          "level": "info"})
                        # Rebuild detected_vulnerabilities
                        _seen = set()
                        _updated_vulns = []
                        for _r in (art["fusion"].get("confirmed", [])
                                   + art["fusion"].get("potential", [])
                                   + art["fusion"].get("ai_discovered", [])):
                            _key = (_r.get("subject"), _r.get("port"))
                            if _key not in _seen:
                                _seen.add(_key)
                                _updated_vulns.append(_r)
                        art["fusion"]["detected_vulnerabilities"] = _updated_vulns
            except Exception as exc:  # noqa: BLE001
                _emit("log", {"text": f"Re-probe loop: {exc}", "level": "warn"})

    # ── Legacy AI analysis (fallback when fusion did not produce AI analysis) ──
    if ai_deep and not fusion_produced_ai:
        from src import ai_analyst
        _emit("progress", {"percent": 99, "status": "AI analysis…"},
              message="Running legacy AI analysis fallback…")
        try:
            art["ai_analysis"] = ai_analyst.analyze_scan(
                host_result, vuln_matches, cfg=_ai_vcfg,
                tls_results=art["tls_results"], header_audit=art["header_audit"],
                stack_result=art["stack_result"], dns_result=art["dns_result"],
                takeover_result=art["takeover_result"], service_probe_result=art["service_probe_result"],
                vuln_probe_result=art["vuln_probe_result"], osint_result=art["osint_result"],
                service_enum_result=art["service_enum_result"], web_fingerprint=art["web_fingerprint"],
                topology=art["topology"], auth_result=art["auth_result"], scan_diff=art["scan_diff"])
            if art["ai_analysis"]:
                _ai = art["ai_analysis"]
                _emit("ai", {"markdown": _ai.markdown, "error": _ai.error,
                             "provider": _ai.provider, "model": _ai.model})
        except Exception as e:
            _emit("log", {"text": f"AI analysis: {e}", "level": "warn"})

    _emit("progress", {"percent": 100, "status": "Scan complete."})
    from src.external.nuclei_runner import extract_cves, extract_exposures, extract_technologies
    nuclei_cves = extract_cves(art.get("nuclei_results") or [])
    nuclei_exposures = extract_exposures(art.get("nuclei_results") or [])
    nuclei_techs = extract_technologies(art.get("nuclei_results") or [])
    _emit("done", {"ports": len(ports_open), "vulns": len(vuln_matches) + len(nuclei_cves),
                   "nuclei_cves": len(nuclei_cves),
                   "nuclei_exposures": len(nuclei_exposures),
                   "nuclei_technologies": len(nuclei_techs),
                   "duration": host_result.scan_duration_s})

    # ── Final reasoning state ──
    try:
        if _ran_director:
            refresh_beliefs(_rs, art)
        else:
            _rs = safe_build_reasoning_state(target, [target], art)
        if _rs is not None:
            art["reasoning"] = _rs.to_dict()
    except Exception:  # noqa: BLE001 — reasoning must never affect a scan
        pass

    return art


def _sensor_applies(ctx, name: str, default: bool) -> bool:
    plan = ctx.extras.get("sensor_plan")
    if plan is None:
        return default
    return plan.get(name, default)


def _run_tls(ctx, target, ports_open):
    from src.tls_analyzer import analyze_tls_ports
    tls_ports = [p.port for p in ports_open if p.tls or p.port in (443, 8443, 993, 995, 465)] or [443]
    ctx.emit("progress", {"percent": 78, "status": "TLS analysis…"}, message="Running TLS analysis…")
    ctx.art["tls_results"] = analyze_tls_ports(target, tls_ports)
    ctx.emit("tls", {"results": [asdict(r) for r in ctx.art["tls_results"]]})


def _run_headers(ctx, target, web_port, audit_headers):
    ctx.emit("progress", {"percent": 82, "status": "HTTP security headers…"}, message="Auditing HTTP security headers…")
    try:
        ctx.art["header_audit"] = audit_headers(target, web_port)
        ctx.emit("headers", asdict(ctx.art["header_audit"]))
    except Exception as e:
        ctx.emit("log", {"text": f"Header audit: {e}", "level": "warn"})


def _run_stack(ctx, target, web_port, fingerprint_stack):
    ctx.emit("progress", {"percent": 85, "status": "Technology stack…"}, message="Fingerprinting technology stack…")
    try:
        ctx.art["stack_result"] = fingerprint_stack(target, web_port)
        ctx.emit("stack", asdict(ctx.art["stack_result"]))
    except Exception as e:
        ctx.emit("log", {"text": f"Stack fingerprint: {e}", "level": "warn"})


def _run_dns(ctx, target, check_dns_security):
    ctx.emit("progress", {"percent": 88, "status": "DNS/email security…"}, message="Checking DNS/email security…")
    try:
        ctx.art["dns_result"] = check_dns_security(target)
        ctx.emit("dns", asdict(ctx.art["dns_result"]))
    except Exception as e:
        ctx.emit("log", {"text": f"DNS/email: {e}", "level": "warn"})


def _run_osint(ctx, target, host_result):
    ctx.emit("progress", {"percent": 90, "status": "Passive OSINT…"}, message="Running passive OSINT…")
    try:
        o = run_osint(target, ip=host_result.ip)
        ctx.art["osint_result"] = o
        ctx.emit("osint", {
            "dns_records": [asdict(r) for r in o.dns_records],
            "subdomains": [asdict(s) for s in o.subdomains],
            "technologies": o.technologies, "emails": o.emails,
            "asn_info": asdict(o.asn_info) if o.asn_info else None,
        })
    except Exception as e:
        ctx.emit("log", {"text": f"OSINT: {e}", "level": "warn"})


def _run_cve_verifier(ctx, host_result, vuln_matches, target, run_verifier_fn):
    obs, allsigs = [], []
    for vm in vuln_matches:
        cves = getattr(vm, "cves", []) or []
        if not cves:
            continue
        try:
            sigs = run_verifier_fn(
                host=host_result.ip or target, port=getattr(vm, "port", 0),
                service=getattr(vm, "service", "") or "", product=getattr(vm, "product", "") or "",
                version=getattr(vm, "version", "") or "",
                cves=[{"id": c.id, "description": c.description, "cvss_score": c.cvss_score,
                       "severity": c.severity, "epss": getattr(c, "epss", 0.0),
                       "exploit_available": c.exploit_available,
                       "references": getattr(c, "references", [])} for c in cves],
                complete=ctx.completer, cfg=ctx.extras.get("ai_vcfg"))
        except Exception:
            sigs = []
        for s in sigs:
            allsigs.append(s)
            obs.append({"node_kind": "cve", "node_key": getattr(s, "claim", ""),
                        "kind": "verifier", "evidence": str(getattr(s, "evidence", ""))[:200],
                        "source": "verifier"})
    if allsigs:
        ctx.art.setdefault("verifier_signals", []).extend(allsigs)
    return obs


def _run_takeover(ctx, target, discover_and_check):
    ctx.emit("progress", {"percent": 92, "status": "Subdomain takeover…"}, message="Checking subdomains for takeover…")
    try:
        ctx.art["takeover_result"] = discover_and_check(target)
        ctx.emit("takeover", asdict(ctx.art["takeover_result"]))
    except Exception as e:
        ctx.emit("log", {"text": f"Takeover: {e}", "level": "warn"})


def _run_probes(ctx, target, ports_open, timeout, probe_services, probe_web_vulnerabilities):
    ctx.emit("progress", {"percent": 94, "status": "Active probes…"}, message="Running active service/vuln probes…")
    try:
        ctx.art["service_probe_result"] = probe_services(target, ports_open, timeout=timeout)
        ctx.emit("service_probes", asdict(ctx.art["service_probe_result"]))
    except Exception as e:
        ctx.emit("log", {"text": f"Service probes: {e}", "level": "warn"})
    try:
        ctx.art["vuln_probe_result"] = probe_web_vulnerabilities(target, ports_open, timeout=timeout)
        ctx.emit("vuln_probes", asdict(ctx.art["vuln_probe_result"]))
    except Exception as e:
        ctx.emit("log", {"text": f"Vuln probes: {e}", "level": "warn"})


def _run_subnet(ctx, host_result, vuln_matches, ports_open, target, timeout, threads,
                probe_subnet, probe_targets, build_subnet_directive, probed_hosts):
    try:
        directive = build_subnet_directive(host_result, vuln_matches)
        if not directive:
            return
        ctx.emit("progress", {"percent": 94, "status": "Subnet probe…"}, message="Probing subnet for related hosts…")
        snet = directive.get("subnet", "")
        ports = directive.get("ports", [p.port for p in ports_open[:5]])
        for ip in probe_subnet(snet, timeout=timeout):
            discovered = probe_targets(ip, ports, timeout=max(timeout, 3.0), threads=threads)
            for hp in discovered:
                probed_hosts.append(hp)
        ctx.art["subnet_probe"] = probed_hosts
    except Exception as e:
        ctx.emit("log", {"text": f"Subnet probe: {e}", "level": "warn"})


def _run_service_enum(ctx, target, ports_open, timeout, enumerate_services):
    ctx.emit("progress", {"percent": 95, "status": "Service exploitability…"}, message="Enumerating service exploitability…")
    try:
        ctx.art["service_enum_result"] = enumerate_services(target, ports_open, timeout=timeout)
        ctx.emit("service_exploitability", asdict(ctx.art["service_enum_result"]))
    except Exception as e:
        ctx.emit("log", {"text": f"Service enum: {e}", "level": "warn"})


def _run_web_fingerprint(ctx, target, http_port, ports_open, timeout, fingerprint_web):
    wscheme = "https" if (http_port in (443, 8443) or
                          any(p.port == http_port and p.tls for p in ports_open)) else "http"
    ctx.emit("progress", {"percent": 96, "status": "Web fingerprint…"}, message="Fingerprinting web application…")
    try:
        ctx.art["web_fingerprint"] = fingerprint_web(target, http_port, wscheme, timeout=max(timeout, 5.0))
        if ctx.art["web_fingerprint"]:
            ctx.emit("web_fingerprint", asdict(ctx.art["web_fingerprint"]))
    except Exception as e:
        ctx.emit("log", {"text": f"Web fingerprint: {e}", "level": "warn"})


def _run_nuclei(ctx, target, ports_open, https_port, timeout, select_nuclei_tags, nuclei_available, nuclei_scan):
    if not nuclei_available():
        return
    try:
        tags = select_nuclei_tags(ports_open, https_port)
        if tags:
            ctx.emit("progress", {"percent": 96, "status": "Nuclei scan…"}, message="Running nuclei template scan…")
            ctx.art["nuclei_results"] = nuclei_scan(target, tags=tags, timeout=timeout)
    except Exception as e:
        ctx.emit("log", {"text": f"Nuclei: {e}", "level": "warn"})


def _run_verifier2(ctx, host_result, target, build_engine_context, reverify_with_context, run_verifier_test, Signal):
    try:
        engine_ctx = build_engine_context(ctx.art)
        plans = reverify_with_context(engine_ctx, complete=ctx.completer)
        if not plans:
            return
        ctx.emit("progress", {"percent": 97, "status": "Verifier phase 2…"}, message="Re-verifying CVEs with full context…")
        signals = []
        for plan in plans[:5]:
            port = plan.get("port", 443)
            result = run_verifier_test(plan, host=host_result.ip or target)
            signals.append(Signal(
                source="verifier", kind="vuln", claim=plan.get("cve_id", "reverify"),
                host=host_result.ip or target, port=port,
                reliability="high", evidence=result.evidence or "re-verified",
                exploit_available=result.success, probe_confirmed=result.success,
                observed_data={"reason": "reverify", "plan": plan, "status": result.status_code},
                exposure={"reachability": "public"}))
        for s in signals:
            ctx.art.setdefault("verifier_signals", []).append(s)
    except Exception as e:
        ctx.emit("log", {"text": f"Verifier phase 2: {e}", "level": "warn"})


def _run_topology(ctx, target, host_result, args, timeout, map_topology):
    ctx.emit("progress", {"percent": 97, "status": "Network topology…"}, message="Mapping network topology…")
    try:
        no_tr = _g(args, "no_traceroute", False)
        ctx.art["topology"] = map_topology(target, host_result.ip,
                                           do_traceroute=not no_tr, timeout=timeout)
        ctx.emit("topology", asdict(ctx.art["topology"]))
    except Exception as e:
        ctx.emit("log", {"text": f"Topology: {e}", "level": "warn"})


def _run_auth_ssh(ctx, target, args, ssh_enumerate):
    ctx.emit("progress", {"percent": 98, "status": "Authenticated SSH enum…"},
             message=f"Authenticated scan: SSH {_g(args, 'ssh_user', '')}@{target}…")
    try:
        ctx.art["auth_result"] = ssh_enumerate(
            target, _g(args, "ssh_user", ""),
            key_path=_g(args, "ssh_key") or None,
            password=_g(args, "ssh_pass") or None,
            port=_g(args, "ssh_port", 22))
        ctx.emit("authenticated", asdict(ctx.art["auth_result"]))
    except Exception as e:
        ctx.emit("log", {"text": f"Authenticated scan: {e}", "level": "warn"})


def _run_diff(ctx, host_result, vuln_matches, target, args, diff_against_last):
    try:
        ctx.art["scan_diff"] = diff_against_last(host_result, vuln_matches, _g(args, "out", "."), target)
        if ctx.art["scan_diff"]:
            ctx.emit("scan_diff", asdict(ctx.art["scan_diff"]))
    except Exception as e:
        ctx.emit("log", {"text": f"Scan diff: {e}", "level": "warn"})


def _run_reachability(ctx, probed_hosts, hosts_ports_from_artifacts, build_reachability):
    try:
        all_targets = list(probed_hosts) + hosts_ports_from_artifacts(ctx.art)
        if all_targets:
            ctx.art["reachability"] = build_reachability(all_targets)
    except Exception as e:
        ctx.emit("log", {"text": f"Reachability: {e}", "level": "warn"})


def build_json_report(art: dict) -> dict:
    """Assemble the full JSON report from a run_scan() artifacts dict."""
    from src.reporter import generate_json_report
    report = generate_json_report(art["host_result"], art["vuln_matches"], art.get("osint_result"))
    sections = {
        "tls": art.get("tls_results"), "headers": art.get("header_audit"),
        "takeover": art.get("takeover_result"), "topology": art.get("topology"),
        "authenticated": art.get("auth_result"), "scan_diff": art.get("scan_diff"),
        "web_fingerprint": art.get("web_fingerprint"),
        "service_exploitability": art.get("service_enum_result"),
        "service_probes": art.get("service_probe_result"), "vuln_probes": art.get("vuln_probe_result"),
        "stack": art.get("stack_result"), "dns": art.get("dns_result"),
    }
    for key, val in sections.items():
        if not val:
            continue
        if key == "tls":
            report["tls"] = [asdict(r) for r in val]
        else:
            report[key] = asdict(val)
    ai = art.get("ai_analysis")
    if ai is not None:
        report["ai_analysis"] = {"markdown": ai.markdown, "error": ai.error,
                                 "provider": ai.provider, "model": ai.model, "tokens": ai.tokens}
    if art.get("fusion") is not None:
        report["fusion"] = art["fusion"]
    if art.get("fusion") and art["fusion"].get("detected_vulnerabilities") and not art.get("ai_analysis"):
        report["detected_vulnerabilities"] = art["fusion"]["detected_vulnerabilities"]
    return report


def _fusion_ai_as_analysis(fusion: dict):
    """Wrap fusion's unified ai_analysis markdown into an AIAnalysis-like object
    so downstream code (emit, json report) treats it identically to the legacy
    ai_analyst.analyze_scan() output."""
    md = fusion.get("ai_analysis")
    if not md:
        return None
    return type("_FakeAnalysis", (), {
        "markdown": md,
        "error": None,
        "provider": "fusion",
        "model": "fusion",
        "tokens": None,
    })()


def _vuln_to_dict(vm) -> dict:
    """Serialise a VulnMatch for the frontend (includes EPSS + confidence)."""
    return {
        "port": vm.port, "service": vm.service, "product": vm.product, "version": vm.version,
        "risk_score": vm.risk_score, "notes": vm.notes,
        "detection_confidence": getattr(vm, "detection_confidence", ""),
        "source": getattr(vm, "source", "nvd"),
        "cves": [{
            "id": c.id, "description": c.description, "cvss_score": c.cvss_score,
            "severity": c.severity, "vector": getattr(c, "vector", ""),
            "published": getattr(c, "published", ""), "exploit_available": c.exploit_available,
            "epss": getattr(c, "epss", 0.0), "epss_percentile": getattr(c, "epss_percentile", 0.0),
            "kev": getattr(c, "kev", False), "cwe": getattr(c, "cwe", ""),
            "has_metasploit": getattr(c, "has_metasploit", False),
            "has_public_exploit": getattr(c, "has_public_exploit", False),
            "version_range": getattr(c, "version_range", ""), "references": getattr(c, "references", []),
        } for c in vm.cves],
    }
