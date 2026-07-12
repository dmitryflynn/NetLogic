"""InvestigationAgent — AI chooses tools; engine executes until budget/stop."""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from src.reasoning.agent.surface import build_surface_summary
from src.reasoning.agent.tools import ToolRuntime, ToolResult

log = logging.getLogger("netlogic.reasoning.agent.loop")

CompleteFn = Callable[[str, str], str]

# ── Prompt modes ──────────────────────────────────────────────────────────────

_SYSTEM_NORMAL = """You are the lead investigator for an AUTHORIZED security assessment.
The deterministic engine already collected a BASELINE surface summary (ports, tech, version/banner
CVE leads). YOU control what happens next.

Rules:
- You ONLY act by calling listed tools. Never invent network results.
- READ-ONLY probes only: GET/HEAD/OPTIONS, UDP query, TLS, DNS. NEVER create/update/delete
  target data or content. No freeform exploits. Session cookies are scanner-side for reads only.
- Prefer proof tools: http_request (optional body_template), param_reflect, cors_probe,
  header_injection_probe, auth_flow_probe, graphql_introspect, api_discover,
  cve_probe, sqli_boolean, sqli_time, ssrf_canary, idor_diff, file_disclosure,
  s3_or_storage_probe, jwt_inspect, subdomain_probe, ssh_banner_timing, ssl_cert_chain,
  dir_enum, browser_get, ssdp_discover/udp_probe, timing_probe, confirm_tech.
- Free-form payloads are FORBIDDEN unless http_proof is listed (Tier C opt-in). When listed:
  use http_proof for crafted GET/HEAD/OPTIONS (or allowlisted POST) to prove a vuln signal only.
  NEVER use freeform to delete/update/wipe data — engine blocks destructive patterns and write methods.
- Otherwise only catalog templates and fixed payload sets.
- smuggling_desync only if listed (requires crash-probe flag).
- After confirming a finding: record_poc (curl), severity_suggest, submit_readiness, scope_check.
- Version/banner CVE hits are LEADS until tool evidence confirms them.
- crash_probe is only available if listed — MAY crash host; still non-write.
- assert_finding status "confirmed" REQUIRES evidence_refs to observation ids from prior tool results.
- Open redirect / CWE-601: confirm ONLY if Location *host* is external (not www/apex same-site
  with attacker URL only in a query string). Quote observed Location in rationale.
- record_poc expected field must quote OBSERVED status/Location — never invent a vulnerable response.
- Build attack chains with chain_link when one finding enables another step.
- When done, call stop with a short summary (or set "stop": true).

Respond with JSON ONLY (no fences, no prose):
{
  "thought": "one short sentence",
  "calls": [{"tool": "<name>", "args": {...}}],
  "findings": [{"id":"...","title":"...","severity":"high|critical|medium|low","status":"confirmed|lead","evidence_refs":["obs_1"],"rationale":"..."}],
  "chains": [{"from":"...","to":"...","why":"..."}],
  "stop": false
}
Max 4 tool calls per turn. Prefer 1-2 high-value calls.
"""

_SYSTEM_DEPTH = """You are the lead investigator for an AUTHORIZED DEPTH-MODE security assessment.
Baseline sensors already ran. YOU drive deeper verification — not inventory tourism.

PRIORITIES (in order):
1. Open CVE / exploitability LEADS in the surface — design tool checks that could prove or refute them.
2. After tech is confirmed ONCE, do NOT re-confirm the same stack. Move to CVE verification, misconfig,
   exposure, and CHAIN building.
3. Prefer discriminating checks: cve_probe for known leads, file_disclosure, param_reflect,
   cors_probe, sqli_boolean/sqli_time on injectable-looking params, idor_diff when two sessions exist,
   ssrf_canary when you have a collaborator host, graphql_introspect, api_discover,
   curated body_template POSTs, timing_probe, raw_tcp on open ports,
   crash_probe/smuggling_desync ONLY if listed.
4. Every productive turn should either (a) produce new network evidence on a lead, or (b) chain_link
   findings into an attack path, or (c) assert_finding with evidence_refs from THIS run's observations.
5. Do NOT stop early. Do NOT stop after only confirming Apache/IIS/nginx. Keep going until CVE leads are
   attempted or the budget note says you may stop.
6. Avoid repeating the same path/tool with identical args. Expand: dir_enum wordlists, browser_get when
   challenged, ssdp_discover/udp_probe for UDP services (e.g. 1900), secondary ports.
7. Never mutate target content. HTTP is GET/HEAD/OPTIONS, or POST only via catalog body_template ids.
   If http_proof is listed (Tier C), freeform GET/query/header (and allowlisted POST) proof is allowed —
   only to expose a vuln signal. Destructive patterns and PUT/PATCH/DELETE are engine-blocked.

Rules:
- ONLY listed tools. Never invent network results.
- assert_finding "confirmed" REQUIRES real observation ids from tool results.
- Prefer non-destructive proof; use crash_probe only when available and relevant.
- Use http_proof when listed for concrete freeform proof of a lead (marker, error leak, redirect).
- Open redirect: Location host must leave the site; same-site bounce + query echo is NOT confirmed.
- When recording PoCs, expected = observed bytes/headers from tools, not a hypothetical response.
- Build attack chains with chain_link whenever one fact enables another step.

Respond with JSON ONLY (no fences, no prose):
{
  "thought": "one short sentence focused on the NEXT high-value lead",
  "calls": [{"tool": "<name>", "args": {...}}],
  "findings": [{"id":"...","title":"...","severity":"high|critical|medium|low","status":"confirmed|lead","evidence_refs":["obs_1"],"rationale":"..."}],
  "chains": [{"from":"...","to":"...","why":"..."}],
  "stop": false
}
Max 4 tool calls per turn. Prefer 2-3 high-value calls when budget remains.
If "stop_blocked" appears in the payload, you MUST continue investigating — stop will be ignored.

EXAMPLE — a CVE lead turn (surface shows IIS 10.0 + CVE-2021-31166 lead, crash_probe listed):
{"thought":"http.sys CVE lead is unverified — send the curated crash probe","calls":[{"tool":"crash_probe","args":{"cve_id":"cve-2021-31166"}}],"findings":[],"chains":[],"stop":false}
NEXT turn, once an observation (e.g. obs_5) shows the vulnerable signal:
{"thought":"crash signal fired — record the confirmed finding and chain it","calls":[],"findings":[{"id":"cve-2021-31166","title":"IIS HTTP.sys RCE confirmed","severity":"critical","status":"confirmed","evidence_refs":["obs_5"],"rationale":"crash_probe returned a vulnerable signal"}],"chains":[{"from":"cve-2021-31166","to":"remote-code-execution","why":"HTTP.sys UAF enables pre-auth RCE"}],"stop":false}
If crash_probe is NOT listed, keep such a CVE a LEAD (status "lead") and pursue other checks — never fabricate a confirmation.
"""

# Depth-mode defaults (applied when agent_depth=True and caller left defaults).
DEPTH_DEFAULT_STEPS = 24
DEPTH_DEFAULT_REQUESTS = 80
DEPTH_MIN_HIGH_VALUE = 10          # high-value tool runs before stop is allowed
DEPTH_MIN_STEPS_BEFORE_STOP = 8    # absolute floor on turns before stop
DEPTH_MAX_STEPS_CAP = 40
DEPTH_MAX_REQUESTS_CAP = 150

_CVE_RE = re.compile(r"cve-\d{4}-\d+", re.I)

# Tools / patterns that count as high-value (depth progress).
_ALWAYS_HIGH_VALUE = frozenset({
    "timing_probe", "raw_tcp", "udp_probe", "ssdp_discover",
    "dir_enum", "browser_get", "crash_probe", "chain_link",
    "set_session",
    # Tier A
    "param_reflect", "cors_probe", "header_injection_probe", "auth_flow_probe",
    "graphql_introspect", "api_discover", "s3_or_storage_probe",
    "subdomain_probe", "ssh_banner_timing", "ssl_cert_chain", "jwt_inspect",
    # Tier B
    "cve_probe", "sqli_boolean", "sqli_time", "ssrf_canary", "idor_diff",
    "file_disclosure", "smuggling_desync",
    # Tier C
    "http_proof",
    # Tier D
    "record_poc", "scope_check", "severity_suggest", "submit_readiness",
})


def _is_high_value(tool: str, args: dict, *, confirmed_techs: set[str]) -> bool:
    """Whether this tool call advances depth (not surface tourism)."""
    t = (tool or "").strip().lower()
    if t in _ALWAYS_HIGH_VALUE:
        return True
    if t == "http_request":
        path = str(args.get("path") or "/").strip() or "/"
        # Curated POST templates are always high-value
        if args.get("body_template") or args.get("template"):
            return True
        # Root GET alone is low-value after baseline; anything else is useful.
        if path not in ("/", ""):
            return True
        headers = args.get("headers") or {}
        if isinstance(headers, dict) and headers:
            return True
        method = str(args.get("method") or "GET").upper()
        if method not in ("GET", "HEAD"):
            return True
        return False
    if t == "confirm_tech":
        tech = str(args.get("tech") or args.get("name") or "").strip().lower()
        # First confirm of a tech is medium value; repeats are not high-value.
        key = tech.split()[0] if tech else ""
        if key and key not in confirmed_techs:
            return True
        return False
    if t == "assert_finding":
        blob = f"{args.get('id', '')} {args.get('title', '')}"
        if _CVE_RE.search(blob) or str(args.get("status") or "").lower() == "confirmed":
            return True
        return False
    if t in ("tls_inspect", "dns_lookup"):
        return True  # once useful for non-web surface
    return False


def _path_seen_key(tool: str, args: dict) -> str | None:
    t = (tool or "").strip().lower()
    if t == "http_request":
        return f"http:{args.get('method', 'GET')}:{args.get('path', '/')}"
    if t == "http_proof":
        return f"proof:{args.get('method', 'GET')}:{args.get('path', '/')}"
    if t == "confirm_tech":
        return f"tech:{args.get('tech') or args.get('name')}"
    if t == "crash_probe":
        return f"crash:{args.get('cve_id') or args.get('cve')}"
    return None


@dataclass
class AgentResult:
    surface: dict = field(default_factory=dict)
    turns: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    chains: list = field(default_factory=list)
    observations: list = field(default_factory=list)
    pocs: list = field(default_factory=list)
    readiness: dict | None = None
    stopped_reason: str = ""
    requests_used: int = 0
    steps_used: int = 0
    depth_mode: bool = False
    high_value_used: int = 0

    def to_dict(self) -> dict:
        return {
            "surface": self.surface,
            "turns": self.turns,
            "findings": self.findings,
            "chains": self.chains,
            "observations": self.observations,
            "pocs": self.pocs,
            "readiness": self.readiness,
            "stopped_reason": self.stopped_reason,
            "requests_used": self.requests_used,
            "steps_used": self.steps_used,
            "depth_mode": self.depth_mode,
            "high_value_used": self.high_value_used,
            "confirmed": sum(1 for f in self.findings if f.get("status") == "confirmed"),
            "leads": sum(1 for f in self.findings if f.get("status") != "confirmed"),
        }


class InvestigationAgent:
    """AI-led tool loop. Completer is (system, user) -> str (JSON).

    depth_mode=True: higher budgets, depth-oriented prompt, early stop blocked until
    enough high-value tool work has been done (CVE/path/timing/chain progress).
    """

    def __init__(
        self,
        completer: CompleteFn | None,
        *,
        max_steps: int = 12,
        max_requests: int = 40,
        allow_crash_probes: bool = False,
        allow_freeform_proof: bool = False,
        depth_mode: bool = False,
        min_high_value: int | None = None,
        min_steps_before_stop: int | None = None,
        emit: Callable | None = None,
    ) -> None:
        self.completer = completer
        self.depth_mode = bool(depth_mode)
        self.allow_crash_probes = allow_crash_probes
        self.allow_freeform_proof = bool(allow_freeform_proof)
        self.emit = emit or (lambda *a, **k: None)

        if self.depth_mode:
            # Raise floors when caller left conservative defaults.
            if max_steps <= 12:
                max_steps = DEPTH_DEFAULT_STEPS
            if max_requests <= 40:
                max_requests = DEPTH_DEFAULT_REQUESTS
            step_cap, req_cap = DEPTH_MAX_STEPS_CAP, DEPTH_MAX_REQUESTS_CAP
            self.min_high_value = (
                DEPTH_MIN_HIGH_VALUE if min_high_value is None else int(min_high_value)
            )
            self.min_steps_before_stop = (
                DEPTH_MIN_STEPS_BEFORE_STOP
                if min_steps_before_stop is None
                else int(min_steps_before_stop)
            )
        else:
            step_cap, req_cap = 30, 100
            self.min_high_value = 0 if min_high_value is None else int(min_high_value)
            self.min_steps_before_stop = 0 if min_steps_before_stop is None else int(min_steps_before_stop)

        self.max_steps = max(1, min(int(max_steps), step_cap))
        self.max_requests = max(1, min(int(max_requests), req_cap))
        self._system = _SYSTEM_DEPTH if self.depth_mode else _SYSTEM_NORMAL

    def _stop_allowed(self, result: AgentResult) -> tuple[bool, str]:
        """Whether the agent is allowed to end early via stop:true."""
        if not self.depth_mode:
            return True, ""
        if result.steps_used < self.min_steps_before_stop:
            return False, (
                f"need at least {self.min_steps_before_stop} steps "
                f"(have {result.steps_used})"
            )
        if result.high_value_used < self.min_high_value:
            return False, (
                f"need {self.min_high_value} high-value tool runs "
                f"(have {result.high_value_used}) — chase CVE leads, non-root paths, "
                f"timing/raw_tcp, chains; do not re-confirm the same tech"
            )
        return True, ""

    def run(
        self,
        *,
        target: str,
        host: str,
        port: int = 80,
        tls: bool = False,
        art: dict | None = None,
        state: Any = None,
        scope: list[str] | None = None,
        http_fn: Callable | None = None,
    ) -> AgentResult:
        surface = build_surface_summary(target, art, scope=scope, state=state)
        if self.depth_mode:
            surface = dict(surface)
            surface["mode"] = "depth"
            surface["depth_goals"] = [
                "Verify or refute each open CVE lead with tools",
                "After one tech confirm, move on — no re-confirm loops",
                "Build attack chains when evidence supports them",
                f"At least {self.min_high_value} high-value tool runs before stop",
            ]
            notes = list(surface.get("notes") or [])
            notes.append(
                "DEPTH MODE: stop is blocked until high-value budget is met. "
                "Prioritize CVE leads over surface path tourism."
            )
            surface["notes"] = notes

        result = AgentResult(surface=surface, depth_mode=self.depth_mode)
        if self.completer is None:
            result.stopped_reason = "no AI completer"
            return result

        runtime = ToolRuntime(
            host=host, port=port, tls=tls,
            scope=scope or surface.get("scope") or [host],
            allow_crash_probes=self.allow_crash_probes,
            allow_freeform_proof=self.allow_freeform_proof,
            http_fn=http_fn,
        )
        catalog = runtime.catalog()
        recent: list[dict] = []
        no_progress = 0
        confirmed_techs: set[str] = set()
        seen_keys: set[str] = set()
        stop_blocks = 0

        for step in range(self.max_steps):
            if result.requests_used >= self.max_requests:
                result.stopped_reason = "request budget exhausted"
                break

            allowed, block_reason = self._stop_allowed(result)
            user_payload = {
                "step": step + 1,
                "max_steps": self.max_steps,
                "requests_used": result.requests_used,
                "max_requests": self.max_requests,
                "depth_mode": self.depth_mode,
                "high_value_used": result.high_value_used,
                "high_value_required": self.min_high_value if self.depth_mode else 0,
                "stop_allowed": allowed,
                "surface": surface,
                "tools": catalog,
                "open_cve_leads": [
                    c for c in (surface.get("cve_leads") or []) if c.get("id")
                ][:20],
                "recent_observations": recent[-16:],
                "findings": runtime.findings,
                "chains": runtime.chains,
                "avoid_repeat": sorted(seen_keys)[-30:],
            }
            if not allowed:
                user_payload["stop_blocked"] = block_reason
                user_payload["instruction"] = (
                    "Continue investigating. Pick the next untested CVE lead or "
                    "a non-root path / timing / secondary port check."
                )

            try:
                from src.reasoning.ai.coordinator import fence  # noqa: PLC0415
                from src.reasoning.ai.normalize import decode_total  # noqa: PLC0415
                raw = self.completer(
                    self._system,
                    fence(json.dumps(user_payload, default=str)[:28000]),
                )
                data = decode_total(raw) if raw else None
            except Exception as exc:  # noqa: BLE001
                log.warning("agent completer failed (%s)", exc)
                result.stopped_reason = f"completer error: {exc}"
                break

            if not isinstance(data, dict):
                no_progress += 1
                if no_progress >= 2:
                    result.stopped_reason = "invalid AI output"
                    break
                continue

            thought = str(data.get("thought") or "")[:300]
            calls = data.get("calls") if isinstance(data.get("calls"), list) else []
            # Inline findings/chains from the model also accepted
            for f in (data.get("findings") or [])[:8]:
                if isinstance(f, dict):
                    if _is_high_value("assert_finding", f, confirmed_techs=confirmed_techs):
                        result.high_value_used += 1
                    runtime.execute("assert_finding", f)
            for c in (data.get("chains") or [])[:8]:
                if isinstance(c, dict):
                    result.high_value_used += 1
                    runtime.execute("chain_link", c)

            turn_results: list[dict] = []
            stop_requested = bool(data.get("stop"))
            executed_network = 0
            turn_high = 0

            for call in calls[:4]:
                if not isinstance(call, dict):
                    continue
                tool = call.get("tool") or call.get("name") or ""
                args = call.get("args") if isinstance(call.get("args"), dict) else {}
                tool_l = str(tool).lower()

                if tool_l == "stop":
                    stop_requested = True
                    summary = args.get("summary") if isinstance(args, dict) else ""
                    tr = runtime.execute("stop", {"summary": summary})
                    turn_results.append(tr.to_dict())
                    break

                # Dedup identical low-value repeats in depth mode
                sk = _path_seen_key(tool_l, args)
                if self.depth_mode and sk and sk in seen_keys and tool_l in (
                    "confirm_tech", "http_request",
                ):
                    # Still allow if http has different headers — key includes method+path only
                    # Skip pure repeats
                    turn_results.append({
                        "ok": False, "tool": tool_l, "summary": f"skipped repeat {sk}",
                        "observation_id": "", "network": False, "error": "repeat",
                    })
                    continue

                if result.requests_used >= self.max_requests:
                    break

                hv = _is_high_value(tool_l, args, confirmed_techs=confirmed_techs)
                tr: ToolResult = runtime.execute(str(tool), args)
                turn_results.append(tr.to_dict())
                if sk:
                    seen_keys.add(sk)
                if tool_l == "confirm_tech" and tr.ok:
                    tech = str(args.get("tech") or args.get("name") or "").lower()
                    if tech:
                        confirmed_techs.add(tech.split()[0] if tech else tech)
                if hv:
                    result.high_value_used += 1
                    turn_high += 1
                if tr.network:
                    result.requests_used += 1
                    executed_network += 1
                    recent.append(tr.to_dict())
                self.emit("agent_tool", {
                    "tool": tr.tool, "ok": tr.ok, "summary": tr.summary,
                    "observation_id": tr.observation_id,
                    "high_value": hv,
                })

            result.steps_used = step + 1
            turn_rec = {
                "step": step + 1, "thought": thought,
                "results": turn_results, "stop": stop_requested,
                "high_value_this_turn": turn_high,
                "high_value_total": result.high_value_used,
            }
            result.turns.append(turn_rec)
            self.emit("agent_turn", turn_rec)

            if stop_requested:
                ok_stop, why = self._stop_allowed(result)
                if ok_stop:
                    result.stopped_reason = "agent stopped"
                    break
                stop_blocks += 1
                # Force continue — tell next turn why
                turn_rec["stop_refused"] = why
                no_progress = 0  # refused stop is not a stall
                # Only bail if the model *only* ever tries to stop and never does work
                # for many turns (avoid infinite stop loops without starving depth).
                if stop_blocks >= 8 and result.high_value_used == 0:
                    result.stopped_reason = f"stop refused repeatedly ({why})"
                    break
                continue

            if not calls and not turn_results:
                no_progress += 1
                if no_progress >= 2:
                    result.stopped_reason = "no progress"
                    break
            else:
                no_progress = 0
            if executed_network == 0 and turn_high == 0 and not any(
                r.get("tool") in ("assert_finding", "chain_link") for r in turn_results
            ):
                no_progress += 1
        else:
            result.stopped_reason = result.stopped_reason or "step budget exhausted"

        result.findings = list(runtime.findings)
        result.chains = list(runtime.chains)
        result.observations = list(runtime.observations)
        result.pocs = list(getattr(runtime, "pocs", None) or [])
        result.readiness = getattr(runtime, "readiness", None)
        # Auto-attach readiness snapshot if agent produced confirmed findings
        if result.findings and result.readiness is None:
            try:
                runtime.execute("submit_readiness", {})
                result.readiness = runtime.readiness
                result.observations = list(runtime.observations)
            except Exception:  # noqa: BLE001
                pass
        mode = "depth" if self.depth_mode else "normal"
        self.emit(
            "agent_done", result.to_dict(),
            message=(
                f"AI agent ({mode}): {result.steps_used} steps, "
                f"{result.high_value_used} high-value, "
                f"{sum(1 for f in result.findings if f.get('status')=='confirmed')} confirmed"
            ),
        )
        return result
