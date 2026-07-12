"""
NetLogic Deep-Probe Mode — multi-agent scan architecture.

Enabled via the ``--deep-probe`` CLI flag or ``deep_probe=True`` API field.
Produces the same ``art`` dict shape as ``engine.run_scan()`` so all existing
report rendering, fusion, and synthesis pipelines work unchanged.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Callable, Optional

from src.scanner import scan_host
from src.cve_correlator import correlate
from src.nvd_lookup import cache_stats

log = logging.getLogger("netlogic.deep")


def _g(args, name, default=None):
    return getattr(args, name, default)


def run_deep_scan(
    target: str,
    ports: list,
    args,
    emit: Optional[Callable] = None,
) -> dict:
    """Deep-probe scan using coordinator + per-service agents.

    Same signature and return shape as ``engine.run_scan()`` — the CLI and
    streaming bridge call it identically. Uses the existing sensor directors
    for planning and the same fusion pipeline for analysis, but executes
    probes through isolated per-service agents.
    """
    def _emit(etype, data=None, message=None):
        if emit is not None:
            emit(etype, data, message)
        elif message:
            print(f"[*] {message}")

    streaming = emit is not None
    timeout = _g(args, "timeout", 2.0)
    threads = _g(args, "threads", 100)
    min_cvss = _g(args, "min_cvss", 4.0)
    full = _g(args, "full", False)
    ai_deep = _g(args, "ai", False)

    do_fusion = _g(args, "fusion", False) or ai_deep

    # ── Port scan ──
    _emit("progress", {"percent": 10, "status": f"Deep-probe scanning {target} ({len(ports)} ports)…"},
          message=f"Deep-probe scanning {target} ({len(ports)} ports)…")

    def _on_port(pr):
        _emit("port", {"target": target, **asdict(pr)})

    host_result = scan_host(target, ports=ports, max_workers=threads, timeout=timeout,
                            on_open_port=_on_port if streaming else None)
    _emit("host", {
        "target": host_result.target, "ip": host_result.ip, "hostname": host_result.hostname,
        "os_guess": host_result.os_guess, "ttl": host_result.ttl,
        "timestamp": host_result.timestamp, "scan_duration_s": host_result.scan_duration_s,
    })

    # ── CVE correlation ──
    n = cache_stats().get("entries", 0)
    _emit("progress", {"percent": 60, "status": "Correlating CVEs…"},
          message=f"Correlating CVEs via NVD API ({'cache: %d entries' % n if n else 'live queries'})…")
    vuln_matches = correlate(host_result.ports, min_cvss=min_cvss, verbose=not streaming)
    for vm in vuln_matches:
        _emit("vuln", {"target": host_result.ip, **_vuln_to_dict(vm)})

    ports_open = host_result.ports

    # ── Artifacts dict (same shape as engine.run_scan) ──
    art: dict = {
        "host_result": host_result, "vuln_matches": vuln_matches,
        "tls_results": [], "header_audit": None, "stack_result": None, "dns_result": None,
        "takeover_result": None, "osint_result": None, "service_probe_result": None,
        "vuln_probe_result": None, "service_enum_result": None, "web_fingerprint": None,
        "topology": None, "auth_result": None, "scan_diff": None, "ai_analysis": None,
        "fusion": None, "nuclei_results": None, "reachability": None,
        "verifier_signals": None, "exploit_chains": None,
    }

    # ── AI config (shared single completer for all agents) ──
    _ai_complete = None
    _ai_vcfg = None
    if ai_deep or full:
        from src import ai_analyst
        from src.fusion.ai import make_completer
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
        except Exception:
            pass

    # ── Coordinator — agent-based probe execution ──
    from src.deep.coordinator import DeepCoordinator

    coordinator = DeepCoordinator(
        art=art,
        host_result=host_result,
        ports_open=ports_open,
        vuln_matches=vuln_matches,
        target=target,
        args=args,
        emit=emit,
        ai_complete=_ai_complete,
        ai_vcfg=_ai_vcfg,
    )
    coordinator.run()

    # ── Fusion pipeline ──
    fusion_produced_ai = False
    if do_fusion:
        _emit("progress", {"percent": 97, "status": "Resolving signals…"},
              message="Fusion: building signals from artifacts…")
        try:
            from src.fusion.engine_bridge import run_fusion
            _emit("progress", {"percent": 98, "status": "Gate + AI adjudication…"},
                  message="Fusion: running gate + AI adjudication…")

            _ai_md_chunks: list[str] = []
            _ai_md_len = 0
            _ai_md_emit_len = 0

            def _on_ai_token(token: str):
                nonlocal _ai_md_chunks, _ai_md_len, _ai_md_emit_len
                _ai_md_chunks.append(token)
                _ai_md_len += len(token)
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

    # ── Re-probe loop ──
    if art.get("fusion") and _ai_complete is not None:
        _potential_items = art["fusion"].get("potential", [])
        if _potential_items:
            from src.directors.reprobe import build_reprobe_plan
            from src.verifier.runner import run_test as _reprobe_executor
            from src.fusion.signals import Signal
            from src.fusion.gate import adjudicate
            from src.fusion.engine_bridge import build_engine_context

            _emit("progress", {"percent": 99, "status": "Re-probing potential items…"},
                  message="Fusion: re-probing potential findings…")
            try:
                _reprobe_plans = build_reprobe_plan(
                    _potential_items,
                    host_context=build_engine_context(art),
                    complete=_ai_complete,
                )
                if _reprobe_plans:
                    _reprobe_signals = []
                    host_ip = getattr(host_result, "ip", None) or target
                    for _plan in _reprobe_plans:
                        _p_port = _plan.get("port", 443)
                        _result = _reprobe_executor(_plan, host=host_ip)
                        _reprobe_signals.append(Signal(
                            source="verifier", kind="vuln",
                            claim=_plan.get("cve_id", "reprobe"),
                            host=host_ip, port=_p_port,
                            reliability="high",
                            evidence=_result.evidence or f"Re-probe: {_plan.get('path', '/')} → {_result.status_code}",
                            exploit_available=_result.success,
                            probe_confirmed=_result.success,
                            observed_data={"reason": "reprobe", "plan": _plan, "status": _result.status_code},
                            exposure={"reachability": "public"},
                        ))
                    if _reprobe_signals:
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
            except Exception as exc:
                _emit("log", {"text": f"Re-probe loop: {exc}", "level": "warn"})

    # ── Legacy AI analysis fallback ──
    if ai_deep and not fusion_produced_ai:
        from src import ai_analyst
        _emit("progress", {"percent": 99, "status": "AI analysis…"},
              message="Running legacy AI analysis fallback…")
        try:
            art["ai_analysis"] = ai_analyst.analyze_scan(
                host_result, vuln_matches, cfg=_ai_vcfg,
                tls_results=art["tls_results"], header_audit=art["header_audit"],
                stack_result=art["stack_result"], dns_result=art["dns_result"],
                takeover_result=art["takeover_result"],
                service_probe_result=art["service_probe_result"],
                vuln_probe_result=art["vuln_probe_result"],
                osint_result=art["osint_result"],
                service_enum_result=art["service_enum_result"],
                web_fingerprint=art["web_fingerprint"],
                topology=art["topology"], auth_result=art["auth_result"],
                scan_diff=art["scan_diff"])
            if art["ai_analysis"]:
                _ai = art["ai_analysis"]
                _emit("ai", {"markdown": _ai.markdown, "error": _ai.error,
                             "provider": _ai.provider, "model": _ai.model})
        except Exception as e:
            _emit("log", {"text": f"AI analysis: {e}", "level": "warn"})

    # ── Exploit chain planning ──
    if art.get("fusion"):
        _emit("progress", {"percent": 99, "status": "Exploit chain planning…"},
              message="Building exploit chains from attack graph…")
        try:
            from src.deep.chain import plan_chains
            host_ip = getattr(host_result, "ip", None) or target
            art["exploit_chains"] = plan_chains(
                art, target, host_ip,
                ai_complete=_ai_complete,
                emit=emit,
            )
            chains = art["exploit_chains"].get("chains", [])
            if chains:
                validated = sum(1 for c in chains if c.get("validated"))
                _emit("log", {"text": f"Exploit chains: {len(chains)} built"
                                      f"{', %d validated' % validated if validated else ''}",
                              "level": "info"})
        except Exception as exc:
            _emit("log", {"text": f"Chain planning: {exc}", "level": "warn"})
            art["exploit_chains"] = {"chains": [], "chain_graph": None, "enabled": False}

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
    return art


def _fusion_ai_as_analysis(fusion: dict):
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
            "version_range": getattr(c, "version_range", ""),
            "references": getattr(c, "references", []),
        } for c in vm.cves],
    }
