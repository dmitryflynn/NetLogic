"""AI-driven verification planner.

Given a target service + its CVEs, the AI generates concrete HTTP-level tests
(path, method, expected response) that would prove the vulnerability is real.
"""

from __future__ import annotations

import json
import logging
from typing import Callable, Optional

log = logging.getLogger("netlogic.verifier.planner")

CompleteFn = Callable[[str, str], str]

_SYSTEM = (
    "You are a penetration testing assistant. Given a CVE and service context, "
    "design a single HTTP request that would RETURN EVIDENCE the vulnerability "
    "actually exists (not just a version banner match).\n\n"
    "RULES:\n"
    "  • Only design tests you are confident will return discriminating evidence.\n"
    "  • If you cannot design a reliable test, set 'skip: true'.\n"
    "  • For path traversal / file read: expect the target file content in the body.\n"
    "  • For SSRF: check for error messages that indicate server-side request processing.\n"
    "  • For RCE: use a safe side-channel (sleep-based timing with ?sleep=5, "
    "or DNS lookup to a canary domain). Default to sleep=3.\n"
    "  • For request smuggling: send a crafted Content-Length + Transfer-Encoding pair "
    "and check for 502/garbled response.\n"
    "  • For open redirect: check if the Location header matches a supplied URL.\n"
    "  • For directory traversal: try /etc/passwd, /windows/win.ini, or similar platform files.\n"
    "  • The expected_status should be 200, 403, 500, or 502 for a vulnerable host — "
    "never 404 (that means the path doesn't exist).\n"
    "  • If a public PoC/exploit reference is provided in the CVE context, derive the "
    "test from it.\n"
    "  • Do NOT suggest nmap, nuclei, metasploit, or external tools — raw HTTP only.\n\n"
    "Return ONE JSON object (no markdown fences):\n"
    "{\n"
    '  "cve_id": "CVE-XXXX-XXXX",\n'
    '  "testable": true|false,\n'
    '  "skip_reason": "why this cannot be tested via HTTP" (only if testable=false),\n'
    '  "method": "GET"|"POST",\n'
    '  "path": "/path/to/test",\n'
    '  "headers": {"Header": "value"} or null,\n'
    '  "body": "request body" or null,\n'
    '  "expected_status": [200, 500],\n'
    '  "expected_body_patterns": ["pattern1", "pattern2"],\n'
    '  "tls": false,\n'
    '  "port": 80,\n'
    '  "evidence_hint": "what to look for in the response to confirm this CVE"\n'
    "}"
)

_BUILTIN_PLANS: dict[str, list[dict]] = {
    # Common Apache CVEs with well-known test paths
    "CVE-2021-40438": [
        {"cve_id": "CVE-2021-40438", "method": "GET",
         "path": "/?unix:///var/run/example.socket|http://127.0.0.1:80/",
         "expected_status": [400, 502], "expected_body_patterns": ["proxy", "request", "error"],
         "port": 80, "tls": False, "evidence_hint": "mod_proxy SSRF — expect 502 Bad Gateway with proxy error"},
    ],
    "CVE-2021-44790": [
        {"cve_id": "CVE-2021-44790", "method": "POST",
         "path": "/", "body": "---",
         "headers": {"Content-Type": "multipart/form-data; boundary=----"},
         "expected_status": [500, 400], "expected_body_patterns": ["error", "Internal Server Error"],
         "port": 80, "tls": False, "evidence_hint": "mod_lua buffer overflow via multipart parser"},
    ],
    "CVE-2023-25690": [
        {"cve_id": "CVE-2023-25690", "method": "GET",
         "path": "/ HTTP/1.1\r\nHost: vulnerable\r\n\r\nGET /?unix://", "tls": False,
         "expected_status": [400, 502], "expected_body_patterns": ["error", "request", "proxy"],
         "port": 80, "evidence_hint": "HTTP request smuggling via mod_proxy"},
    ],
    "CVE-2022-22720": [
        {"cve_id": "CVE-2022-22720", "method": "GET",
         "path": "/", "headers": {"Transfer-Encoding": "chunked", "Content-Length": "5"},
         "expected_status": [400, 502], "expected_body_patterns": ["error", "request"],
         "port": 80, "tls": False, "evidence_hint": "HTTP request smuggling via unclosed connections"},
    ],
    "CVE-2019-0211": [
        {"cve_id": "CVE-2019-0211", "method": "GET",
         "path": "/server-status",
         "expected_status": [200, 403],
         "expected_body_patterns": ["apache", "server", "status"],
         "port": 80, "tls": False, "evidence_hint": "CARPE DIEM — check if mod_status exposes server-status"},
    ],
    "CVE-2024-38475": [
        {"cve_id": "CVE-2024-38475", "method": "GET",
         "path": "/?%7", "expected_status": [400, 500, 502],
         "expected_body_patterns": ["error", "Internal Server Error"],
         "port": 80, "tls": False, "evidence_hint": "mod_rewrite improper escaping"},
    ],
    "CVE-2024-38476": [
        {"cve_id": "CVE-2024-38476", "method": "GET",
         "path": "/.htaccess", "expected_status": [200, 403],
         "expected_body_patterns": ["denied", "forbidden", "htaccess"],
         "port": 80, "tls": False, "evidence_hint": "information disclosure via core"},
    ],
    "CVE-2024-38477": [
        {"cve_id": "CVE-2024-38477", "method": "GET",
         "path": "/.htpasswd", "expected_status": [200, 403],
         "expected_body_patterns": ["denied", "forbidden"],
         "port": 80, "tls": False, "evidence_hint": "null pointer dereference in mod_proxy"},
    ],
    "CVE-2021-39275": [
        {"cve_id": "CVE-2021-39275", "method": "GET",
         "path": "/%5c..%5c..%5c../windows/win.ini",
         "expected_status": [200, 400], "expected_body_patterns": ["fonts", "extensions"],
         "port": 80, "tls": False, "evidence_hint": "ap_escape_quotes buffer overflow path traversal"},
    ],
    "CVE-2021-26691": [
        {"cve_id": "CVE-2021-26691", "method": "GET",
         "path": "/", "headers": {"Session": "malicious"},
         "expected_status": [500, 400], "expected_body_patterns": ["error", "Internal"],
         "port": 80, "tls": False, "evidence_hint": "mod_session heap overflow via crafted Session header"},
    ],
    "CVE-2022-22721": [
        {"cve_id": "CVE-2022-22721", "method": "GET",
         "path": "/", "headers": {"Content-Length": str(1024 * 1024 * 400)},
         "expected_status": [400, 413, 500],
         "expected_body_patterns": ["error", "large", "limit"],
         "port": 80, "tls": False, "evidence_hint": "LimitXMLRequestBody integer overflow on 32-bit"},
    ],
    "CVE-2019-0217": [
        {"cve_id": "CVE-2019-0217", "method": "GET",
         "path": "/", "headers": {"Authorization": "Digest "},
         "expected_status": [400, 401, 500],
         "expected_body_patterns": ["error", "digest", "Unauthorized"],
         "port": 80, "tls": False, "evidence_hint": "race condition in mod_auth_digest"},
    ],
    # SSH CVEs (can't test via HTTP, but can try banner manipulation)
    "CVE-2023-38408": [
        {"cve_id": "CVE-2023-38408", "protocol": "ssh",
         "method": "GET", "path": "/", "tls": False,
         "expected_status": [], "expected_body_patterns": [],
         "port": 22, "evidence_hint": "OpenSSH agent RCE — requires SSH agent forwarding, not testable via HTTP"},
    ],
}


def _find_builtin(cve_id: str) -> Optional[list[dict]]:
    for key, plans in _BUILTIN_PLANS.items():
        if key == cve_id or cve_id.startswith(key) or key.startswith(cve_id):
            return plans
    return None


def generate_plans_for_cves(cves: list[dict], service: str, product: str, version: str,
                            port: int, use_tls: bool = False,
                            complete: Optional[CompleteFn] = None,
                            cfg=None) -> list[dict]:
    """Given a list of CVE dicts (with id, cvss, description, references, etc.),
    return a list of verification plans (dicts ready for runner.run_test()).

    Uses built-in plans for well-known CVEs. Falls back to AI generation for
    unknown ones if an AI completer is available.
    """
    plans: list[dict] = []

    for cve in cves:
        cve_id = cve.get("id", "unknown")
        desc = cve.get("description", "") or ""

        # Skip low-impact or info-only CVEs
        cvss = float(cve.get("cvss_score", 0) or 0)
        if cvss < 7.0:
            continue

        # Check built-in plans first
        builtin = _find_builtin(cve_id)
        if builtin:
            for bp in builtin:
                p = dict(bp)
                p.setdefault("port", port)
                p.setdefault("tls", use_tls)
                p.setdefault("cve_id", cve_id)
                plans.append(p)
            continue

        # Try AI generation
        if complete is not None:
            try:
                ai_plan = _ask_ai(cve, service, product, version, complete)
                if ai_plan and ai_plan.get("testable"):
                    ai_plan.setdefault("port", port)
                    ai_plan.setdefault("tls", use_tls)
                    plans.append(ai_plan)
                elif ai_plan and ai_plan.get("skip_reason"):
                    log.debug("AI skipped %s: %s", cve_id, ai_plan.get("skip_reason"))
                continue
            except Exception as e:
                log.warning("AI planner failed for %s: %s", cve_id, e)

        # No plan — skip
        log.debug("No verification plan for %s (no builtin, no AI)", cve_id)

    return plans


def _ask_ai(cve: dict, service: str, product: str, version: str,
            complete: CompleteFn) -> Optional[dict]:
    cve_id = cve.get("id", "unknown")
    desc = cve.get("description", "")[:400]
    cvss = cve.get("cvss_score", "?")
    refs = cve.get("references", [])
    ref_str = ""
    if isinstance(refs, list) and refs:
        ref_str = "\nReferences: " + "\n  ".join(str(r)[:120] for r in refs[:3])

    user = (
        f"CVE: {cve_id}\n"
        f"CVSS: {cvss}\n"
        f"Service: {service}\n"
        f"Product: {product}\n"
        f"Version: {version}\n"
        f"Description: {desc}\n"
        f"{ref_str}\n\n"
        "Design a single raw-HTTP verification test (no tools). "
        "Return the JSON plan."
    )

    try:
        text = complete(_SYSTEM, user).strip()
    except Exception as e:
        log.warning("AI call failed: %s", e)
        return None

    return _parse_plan(text, cve_id)


def _parse_plan(text: str, cve_id: str) -> Optional[dict]:
    from src.fusion.ai import robust_json_array

    arr = robust_json_array(text)
    if isinstance(arr, list) and arr:
        return arr[0]
    # Try single object parse
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    log.warning("Could not parse planner output for %s: %.200s", cve_id, text)
    return None


_VERIFY_SYSTEM = (
    "You are a penetration testing assistant. Given CVE IDs that failed "
    "initial verification, the initial probe results, and FULL HOST CONTEXT "
    "(HTTP responses, TLS state, headers, tech stack, DNS), design refined "
    "probe plans that might succeed where the initial ones failed.\n\n"
    "RULES:\n"
    "  • Use the host context to design better probes — real HTTP response "
    "data, known headers, tech stack versions, and TLS state.\n"
    "  • If the initial probe got a 403 (forbidden), try a different path "
    "or method based on the known tech stack.\n"
    "  • If the initial probe got a 404 (not found), the path doesn't exist "
    "— choose a different path based on CVE details and tech stack.\n"
    "  • If a CVE still cannot be tested, set 'skip: true'.\n"
    "  • Return ONE JSON array of probe plan objects (same format as "
    "initial plans), one per resolvable CVE.\n"
    "  • If no CVEs can be resolved with current context, return []\n"
    '  • Each plan: {"cve_id": "...", "method": "GET", "path": "/", '
    '"expected_status": [200], "expected_body_patterns": [...], '
    '"port": 80, "tls": false, "evidence_hint": "..."}'
)


def reverify_with_context(
    cve_ids: list[str],
    phase1_results: list[dict],
    context: Optional[dict] = None,
    complete: Optional[CompleteFn] = None,
) -> list[dict]:
    """Refine verification plans using full host context.

    Takes CVE IDs that failed Phase 1 verification, the Phase 1 results,
    and the full host context (build_engine_context output). Returns new
    probe plans that may succeed with enriched context.
    """
    if not cve_ids or complete is None:
        return []

    parts = ["CVEs needing re-verification: " + ", ".join(cve_ids)]
    if phase1_results:
        parts.append("PHASE 1 RESULTS:\n```json\n" + json.dumps(phase1_results, indent=2, default=str) + "\n```")
    if context:
        parts.append("HOST CONTEXT:\n```json\n" + json.dumps(context, indent=2, default=str) + "\n```")
    parts.append("Design refined verification probes for each CVE.")
    user = "\n\n".join(parts)

    try:
        text = complete(_VERIFY_SYSTEM, user).strip()
    except Exception as e:
        log.warning("Reverify AI call failed: %s", e)
        return []

    from src.fusion.ai import robust_json_array
    arr = robust_json_array(text)
    if not isinstance(arr, list):
        log.warning("Reverify parse failed: expected array, got %.200s", text)
        return []
    plans = []
    for obj in arr:
        if not isinstance(obj, dict):
            continue
        if obj.get("skip"):
            continue
        plan = {
            "cve_id": str(obj.get("cve_id", "unknown")),
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
        plans.append(plan)
    return plans
