"""
NetLogic - AI Analyst
=====================
Optional LLM-powered analysis layer. Takes the structured output of a scan
(open ports, product/version detection, correlated CVEs, misconfigurations,
TLS/DNS/header findings) and asks an LLM to produce a prioritized, human-readable
assessment: executive summary, ranked findings, likely attack paths, and
concrete remediation.

Design goals
------------
* **No third-party dependencies** — uses only the standard library (urllib),
  so it works in the same frozen/offline-friendly environment as the scanner.
* **Provider-agnostic** — speaks the OpenAI-compatible Chat Completions API used
  by OpenRouter, OpenAI, Groq, Together, LM Studio, and Ollama, plus native
  support for the Anthropic Messages API.
* **Fail-soft** — any network/credential error returns an ``AIAnalysis`` with an
  ``error`` set instead of raising, so a failed AI call never breaks a scan.

Configuration (in precedence order: explicit AIConfig > env):
    NETLOGIC_AI_API_KEY  | OPENROUTER_API_KEY | OPENAI_API_KEY | ANTHROPIC_API_KEY
                         | KIMI_API_KEY | MOONSHOT_API_KEY | DASHSCOPE_API_KEY
    NETLOGIC_AI_PROVIDER  (openrouter|openai|anthropic|kimi|qwen|groq|ollama|custom)
    NETLOGIC_AI_MODEL
    NETLOGIC_AI_BASE_URL  (required for provider=custom)
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

# Upstream errors that are worth retrying: gateway/timeout/overload/rate-limit.
# A 504 ("Provider returned error") from OpenRouter is the common one — the model
# backend timed out and the same request usually succeeds on a second attempt.
_RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}
_MAX_AI_ATTEMPTS = 3
_RETRY_BACKOFF_SECONDS = (2.0, 5.0)   # waits between attempts 1→2 and 2→3


class _TransientAIError(Exception):
    """A retryable upstream error (gateway timeout, overload, rate limit)."""

    def __init__(self, message: str, status: Optional[int] = None) -> None:
        super().__init__(message)
        self.status = status


# ─── Provider presets ─────────────────────────────────────────────────────────
# name -> (base_url, default_model, api_style)
PROVIDER_PRESETS: dict[str, tuple[str, str, str]] = {
    "openrouter": ("https://openrouter.ai/api/v1", "anthropic/claude-sonnet-4", "openai"),
    "openai":     ("https://api.openai.com/v1",    "gpt-4o-mini",                 "openai"),
    "anthropic":  ("https://api.anthropic.com",    "claude-3-5-sonnet-20241022",  "anthropic"),
    "kimi":       ("https://api.moonshot.ai/v1",    "kimi-k2.6",                  "openai"),
    "qwen":       ("https://dashscope-intl.aliyuncs.com/compatible-mode/v1", "qwen-plus", "openai"),
    "groq":       ("https://api.groq.com/openai/v1","llama-3.3-70b-versatile",    "openai"),
    "ollama":     ("http://localhost:11434/v1",    "llama3",                      "openai"),
}

ALLOWED_PROVIDERS = set(PROVIDER_PRESETS) | {"custom"}

PROVIDER_KEY_ENV_VARS: dict[str, tuple[str, ...]] = {
    "openrouter": ("OPENROUTER_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "kimi": ("KIMI_API_KEY", "MOONSHOT_API_KEY"),
    "qwen": ("DASHSCOPE_API_KEY", "QWEN_API_KEY"),
    "groq": ("GROQ_API_KEY",),
    "custom": (),
    "ollama": (),
}


def _clean(value: Optional[str]) -> Optional[str]:
    value = (value or "").strip()
    return value or None


def _key_from_env(provider: str) -> Optional[str]:
    for var in ("NETLOGIC_AI_API_KEY", *PROVIDER_KEY_ENV_VARS.get(provider, ())):
        if os.environ.get(var):
            return os.environ[var]
    return None


# ─── Config + result models ───────────────────────────────────────────────────

@dataclass
class AIConfig:
    api_key: Optional[str] = None
    provider: str = "openrouter"
    model: Optional[str] = None
    base_url: Optional[str] = None
    timeout: float = 90.0
    # Room for a full strictly-formatted report (findings table + attack chains +
    # remediation) without truncation. Low temperature for consistent structure.
    max_tokens: int = 8000
    temperature: float = 0.15

    def resolve(self) -> "AIConfig":
        """Fill in provider preset defaults; returns self for chaining."""
        preset = PROVIDER_PRESETS.get(self.provider)
        if preset:
            base, model, _style = preset
            if not self.base_url:
                self.base_url = base
            if not self.model:
                self.model = model
        return self

    @property
    def api_style(self) -> str:
        preset = PROVIDER_PRESETS.get(self.provider)
        if preset:
            return preset[2]
        # custom/unknown provider — infer from base_url, default to OpenAI shape
        if self.base_url and "anthropic" in self.base_url:
            return "anthropic"
        return "openai"

    def is_usable(self) -> tuple[bool, str]:
        if self.provider not in ALLOWED_PROVIDERS:
            return False, (
                f"Unsupported AI provider '{self.provider}'. Use one of: "
                + ", ".join(sorted(ALLOWED_PROVIDERS))
            )
        if not self.api_key and self.provider != "ollama":
            envs = ", ".join(("NETLOGIC_AI_API_KEY", *PROVIDER_KEY_ENV_VARS.get(self.provider, ())))
            return False, f"No AI API key for provider '{self.provider}'. Paste a key or set {envs}."
        if not self.base_url:
            return False, f"No base URL for provider '{self.provider}' (use --ai-base-url for custom)."
        if not self.model:
            return False, f"No model selected for provider '{self.provider}' (use --ai-model)."
        return True, ""


@dataclass
class AIAnalysis:
    markdown: str = ""
    error: Optional[str] = None
    model: str = ""
    provider: str = ""
    tokens: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.error is None and bool(self.markdown)


# ─── Config construction ──────────────────────────────────────────────────────

def config_from_env() -> AIConfig:
    """Build an AIConfig from environment variables."""
    provider = (os.environ.get("NETLOGIC_AI_PROVIDER") or "openrouter").lower().strip()
    cfg = AIConfig(
        api_key=_key_from_env(provider),
        provider=provider,
        model=_clean(os.environ.get("NETLOGIC_AI_MODEL")),
        base_url=_clean(os.environ.get("NETLOGIC_AI_BASE_URL")),
    )
    return cfg.resolve()


def fusion_has_separate_config() -> bool:
    """True if a fusion-specific provider/key is configured (vs inheriting the AI one)."""
    return bool(os.environ.get("NETLOGIC_FUSION_API_KEY") or os.environ.get("NETLOGIC_FUSION_PROVIDER"))


def fusion_config_from_env() -> AIConfig:
    """AI config for the FUSION adjudicator. Reads NETLOGIC_FUSION_* so it can use a
    different provider/model/key than the AI-analyst report. Falls back to the AI
    config when no fusion-specific settings are present (one key powers both)."""
    if not fusion_has_separate_config():
        return config_from_env()
    provider = (os.environ.get("NETLOGIC_FUSION_PROVIDER") or "openrouter").lower().strip()
    key = os.environ.get("NETLOGIC_FUSION_API_KEY") or _key_from_env(provider)
    cfg = AIConfig(
        api_key=key,
        provider=provider,
        model=_clean(os.environ.get("NETLOGIC_FUSION_MODEL")),
        base_url=_clean(os.environ.get("NETLOGIC_FUSION_BASE_URL")),
    )
    return cfg.resolve()


def build_config(api_key: Optional[str] = None, provider: Optional[str] = None,
                 model: Optional[str] = None, base_url: Optional[str] = None) -> AIConfig:
    """Merge explicit CLI overrides over environment defaults."""
    cfg = config_from_env()
    provider = _clean(provider)
    model = _clean(model)
    base_url = _clean(base_url)
    api_key = _clean(api_key)

    if provider:
        cfg.provider = provider.lower()
        cfg.api_key = api_key or _key_from_env(cfg.provider)
        cfg.base_url = base_url
        cfg.model = model
    elif api_key:
        cfg.api_key = api_key
    if model:
        cfg.model = model
    if base_url:
        cfg.base_url = base_url
    return cfg.resolve()


# ─── Findings summarization ───────────────────────────────────────────────────

def _b(obj, attr, default=None):
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def summarize_findings(host_result, vuln_matches=None, *, tls_results=None,
                       header_audit=None, stack_result=None, dns_result=None,
                       takeover_result=None, service_probe_result=None,
                       vuln_probe_result=None, osint_result=None,
                       service_enum_result=None, web_fingerprint=None,
                       topology=None, auth_result=None, scan_diff=None,
                       max_cves: int = 30) -> dict:
    """Build a compact, JSON-serializable dict of the scan for the LLM prompt."""
    data: dict[str, Any] = {
        "target": _b(host_result, "target"),
        "ip": _b(host_result, "ip"),
        "os_guess": _b(host_result, "os_guess"),
        "open_ports": [],
        "vulnerabilities": [],
    }

    for p in _b(host_result, "ports", []) or []:
        banner = _b(p, "banner")
        entry = {
            "port": _b(p, "port"),
            "protocol": _b(p, "protocol", "tcp"),
            "service": _b(p, "service"),
            "product": _b(banner, "product") if banner else None,
            "version": _b(banner, "version") if banner else None,
            "tls": _b(p, "tls", False),
            "detection_confidence": _b(p, "detection_confidence"),
        }
        if _b(p, "tls_cert_cn"):
            entry["tls_cert_cn"] = _b(p, "tls_cert_cn")
        if _b(p, "protocol_fingerprint"):
            entry["udp_protocol"] = _b(p, "protocol_fingerprint")
        data["open_ports"].append(entry)

    # Flatten + rank CVEs so the model sees the scariest first within a budget.
    # Carry per-finding match confidence so the AI can weight version-CONFIRMED
    # (HIGH) findings over unverified version guesses (POTENTIAL).
    cve_rows = []
    for vm in (vuln_matches or []):
        match_conf = _b(vm, "detection_confidence", "")
        for c in _b(vm, "cves", []) or []:
            cve_rows.append({
                "port": _b(vm, "port"),
                "service": _b(vm, "service"),
                "product": _b(vm, "product"),
                "version": _b(vm, "version"),
                "id": _b(c, "id"),
                "cvss": _b(c, "cvss_score"),
                "severity": _b(c, "severity"),
                "match_confidence": match_conf,   # HIGH=version-confirmed, POTENTIAL=unverified
                "kev": _b(c, "kev", False),
                "epss": round(_b(c, "epss", 0.0) or 0.0, 4),          # P(exploited in 30d), 0-1
                "epss_percentile": round(_b(c, "epss_percentile", 0.0) or 0.0, 3),
                "exploit": _b(c, "has_metasploit", False) or _b(c, "has_public_exploit", False)
                           or _b(c, "exploit_available", False),
                "desc": (_b(c, "description", "") or "")[:240],
            })
    cve_rows.sort(key=lambda r: (r["kev"], r["epss"], r["exploit"], r["cvss"] or 0), reverse=True)
    data["vulnerabilities"] = cve_rows[:max_cves]
    data["vulnerability_count_total"] = len(cve_rows)

    # Notes / misconfigurations attached to vuln matches
    notes = []
    for vm in (vuln_matches or []):
        for n in _b(vm, "notes", []) or []:
            notes.append({"port": _b(vm, "port"), "note": n})
    if notes:
        data["notes"] = notes

    if header_audit is not None:
        data["http_headers"] = {
            "grade": _b(header_audit, "grade"),
            "score": _b(header_audit, "score"),
            "missing": _b(header_audit, "headers_missing", []),
        }
    if tls_results:
        tls_rows = []
        for t in tls_results:
            cert = _b(t, "cert")
            row = {
                "port": _b(t, "port"),
                "grade": _b(t, "grade"),
                "protocols_supported": _b(t, "protocols_supported", []),
                "protocols_deprecated": _b(t, "protocols_deprecated", []),
                "cipher": _b(t, "cipher_suite"),
                "weak_ciphers": _b(t, "weak_ciphers_detected", []),
            }
            if cert is not None:
                row["cert"] = {
                    "subject_cn": _b(cert, "subject_cn"),
                    "issuer_cn": _b(cert, "issuer_cn"),
                    "expires": _b(cert, "not_after"),
                    "days_until_expiry": _b(cert, "days_until_expiry"),
                    "self_signed": _b(cert, "is_self_signed"),
                    "expired": _b(cert, "is_expired"),
                    "key_bits": _b(cert, "key_bits"),
                    "sig_algorithm": _b(cert, "sig_algorithm"),
                    # SANs reveal sibling hostnames / infrastructure (topology).
                    "san_domains": (_b(cert, "san_domains", []) or [])[:15],
                }
            tls_rows.append(row)
        data["tls"] = tls_rows
    if stack_result is not None:
        techs = _b(stack_result, "technologies", []) or []
        data["tech_stack"] = [f"{_b(t,'name')} {_b(t,'version') or ''}".strip() for t in techs]
        waf = _b(stack_result, "waf")
        if waf and _b(waf, "detected"):
            data["waf"] = _b(waf, "name")
        cdn = _b(stack_result, "cdn")
        cloud = _b(stack_result, "cloud_provider")
        if cdn or cloud:
            data["edge"] = {"cdn": cdn, "cloud": cloud}
            # Origin-vs-edge caveat: behind a CDN/proxy the Server banner is the
            # edge, not the backend — version-matched CVEs may not apply to origin.
            data["origin_caveat"] = (
                f"A {cdn or cloud} edge/CDN fronts this host. The version banner may be "
                "the edge, not the origin server — treat version-only CVE matches with "
                "extra caution unless confirmed against the backend.")
    if dns_result is not None:
        data["dns_email_security"] = {
            "spoofability_score": _b(dns_result, "spoofability_score"),
            "email_spoofable": _b(dns_result, "email_spoofable"),
        }
    if takeover_result is not None:
        vuln = _b(takeover_result, "vulnerable", []) or []
        if vuln:
            data["subdomain_takeover"] = [_b(f, "subdomain") for f in vuln]
    if service_probe_result is not None:
        data["service_misconfigs"] = [{
            "port": _b(f, "port"), "title": _b(f, "title"), "severity": _b(f, "severity"),
        } for f in (_b(service_probe_result, "findings", []) or [])]
    if vuln_probe_result is not None:
        data["confirmed_vulns"] = [{
            "cve": _b(f, "cve_id"), "title": _b(f, "title"), "confirmed": _b(f, "confirmed"),
        } for f in (_b(vuln_probe_result, "confirmed", []) or [])]
    if osint_result is not None:
        subs = _b(osint_result, "subdomains", []) or []
        if subs:
            data["subdomains_found"] = len(subs)

    # Network topology — context for lateral-movement reasoning.
    if topology is not None:
        topo = {
            "reverse_dns": _b(topology, "ptr"),
            "asn": _b(topology, "asn"),
            "asn_org": _b(topology, "asn_org"),
            "country": _b(topology, "country"),
            "ipv6": _b(topology, "ipv6", []),
            "hop_count": _b(topology, "hop_count"),
        }
        data["topology"] = {k: v for k, v in topo.items() if v}

    # Authenticated facts — installed package versions are GROUND TRUTH (patch-level),
    # not banner guesses. 'backported' means the distro patched it despite an old version.
    if auth_result is not None and _b(auth_result, "success"):
        data["authenticated"] = {
            "os": _b(auth_result, "os_name"),
            "kernel": _b(auth_result, "kernel"),
            "installed_versions": _b(auth_result, "product_versions", {}),
            "note": "These are AUTHENTICATED installed versions (ground truth). Prefer them "
                    "over banner versions. 'backported': true means the distro applied security "
                    "fixes without changing the upstream version — such CVEs are likely PATCHED.",
        }

    # Change since the last scan — where fresh exposure appears.
    if scan_diff is not None and _b(scan_diff, "has_changes"):
        data["changes_since_last_scan"] = {
            "ports_added": _b(scan_diff, "ports_added", []),
            "ports_removed": _b(scan_diff, "ports_removed", []),
            "version_changes": _b(scan_diff, "version_changes", []),
            "new_cves": _b(scan_diff, "cves_added", []),
            "resolved_cves": _b(scan_diff, "cves_removed", []),
        }

    # Web application fingerprint — favicon hash, generator, exact version markers,
    # exposed files, and anything leaked in served JS (endpoints/secrets).
    if web_fingerprint is not None:
        wf = {
            "favicon_mmh3": _b(web_fingerprint, "favicon_mmh3"),
            "generator": _b(web_fingerprint, "generator"),
            "app_name": _b(web_fingerprint, "app_name"),
            "title": _b(web_fingerprint, "title"),
            "version_markers": _b(web_fingerprint, "version_markers", []),
            "exposed_files": _b(web_fingerprint, "exposed_files", []),
            "js_endpoints": _b(web_fingerprint, "js_endpoints", []),
            "js_secrets": _b(web_fingerprint, "js_secrets", []),
            "notes": _b(web_fingerprint, "notes", []),
        }
        data["web_fingerprint"] = {k: v for k, v in wf.items() if v}

    # Protocol-level exploitability attributes — the preconditions that decide
    # whether a version-matched CVE is actually reachable/exploitable.
    if service_enum_result is not None:
        attrs = _b(service_enum_result, "attributes", []) or []
        if attrs:
            data["exploitability"] = [{
                "port": _b(a, "port"),
                "service": _b(a, "service"),
                "attribute": _b(a, "attribute"),
                "value": _b(a, "value"),
                "severity": _b(a, "severity"),
                "enables_cves": _b(a, "exploit_precondition_for", []),
                "detail": _b(a, "detail"),
            } for a in attrs]

    return data


# ─── Prompt ───────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a senior penetration tester analyzing the output of an AUTHORIZED "
    "assessment by the NetLogic scanner. The JSON gives you detailed facts: host "
    "OS estimate, open ports and protocols, detected products and versions, "
    "TLS/protocol versions, technology stack, DNS/email posture, network topology "
    "(subdomains), plus correlated CVE leads and any probe-CONFIRMED findings.\n\n"
    "Your job is INTERPRETATION — the scanner reports facts and leads; YOU decide "
    "what is likely real and how it chains together. Reason like an attacker about "
    "this SPECIFIC host using ALL the evidence (OS + service + version + protocol + "
    "topology), not generic advice.\n\n"
    "CRITICAL — GO BEYOND KNOWN CVEs. The CVE leads are only the floor. A host that "
    "has patched every known CVE can still be attackable. You MUST also reason about:\n"
    "  • Non-CVE weaknesses: exposed admin/management interfaces, dangerous services "
    "reachable without auth, information disclosure, weak/legacy protocols, default or "
    "guessable configurations, permissive CORS/headers, secrets leaked in served JS, "
    "overly large attack surface.\n"
    "  • Undiscovered / zero-day-class risk: where the detected stack is END-OF-LIFE, "
    "unmaintained, a known-fragile class of software (custom web apps, deserialization-"
    "heavy frameworks, file-upload endpoints, exposed RPC/IPC), or simply old enough "
    "that unpatched-but-undisclosed bugs are LIKELY. State these as HYPOTHESES with your "
    "reasoning — never as confirmed CVEs and never with an invented CVE ID.\n"
    "  • Emergent risk from CHAINING individually-benign facts: a single fact may be "
    "harmless, but combined with others it becomes an attack path (e.g. an info leak + "
    "an exposed login + password reuse signal; a verbose error + a known framework; an "
    "internal hostname in a cert SAN + an open management port). This combinational "
    "reasoning is the MAIN value you add — actively look for it.\n\n"
    "Weight the evidence by confidence:\n"
    "  • match_confidence=HIGH or a probe-confirmed finding → treat as real.\n"
    "  • match_confidence=POTENTIAL → a version/heuristic LEAD that may be a false "
    "positive (patched, backported, or coarse version); say so, don't assert it.\n"
    "  • CISA KEV / public-exploit CVEs → call out as urgent IF the match is credible.\n"
    "  • EPSS is the probability (0–1) a CVE is exploited in the wild — use it to "
    "PRIORITISE: a high-EPSS (>0.1) or KEV CVE matters far more than a CVSS-9.8 with "
    "EPSS near 0. Lead with high-EPSS/KEV findings; treat low-EPSS criticals as lower "
    "priority even if the CVSS is high.\n"
    "  • The 'exploitability' list gives protocol-level PRECONDITIONS (e.g. SMBv1 "
    "enabled, RDP NLA not required, SNMP default community, web surface open vs "
    "auth-gated). Use them decisively: if a CVE's precondition is CONFIRMED present "
    "(via enables_cves), promote it to a real finding; if the precondition is absent "
    "or the surface is auth-gated, downgrade or discard the version-only match.\n"
    "  • 'web_fingerprint' (generator/version_markers/favicon/exposed_files/js_secrets) "
    "is precise CONTENT evidence — prefer its exact versions over the coarse banner, "
    "and treat exposed_files / js_secrets as real findings.\n"
    "  • If 'origin_caveat' is present, a CDN/proxy fronts the host — be cautious that "
    "version-banner CVEs may target the edge, not the origin.\n"
    "  • 'authenticated' (if present) is GROUND TRUTH — installed package versions read "
    "over SSH. Override banner versions with these. If a package is 'backported', the "
    "distro patched it despite an old-looking version → treat its version-only CVEs as "
    "likely PATCHED unless proven otherwise.\n"
    "  • 'changes_since_last_scan' (if present) is high-signal: new ports/versions/CVEs "
    "are where fresh exposure appears — call them out prominently.\n"
    "  • Use 'topology' (ASN/reverse-DNS/IPv6/hops) to reason about blast radius and "
    "lateral movement, not just the single host.\n\n"
    "═══ OUTPUT CONTRACT (follow EXACTLY) ═══\n"
    "Respond in GitHub-Flavored Markdown ONLY — no preamble, no sign-off, no text "
    "outside the sections below. Use these six `##` sections, in this exact order "
    "and with these exact titles:\n\n"
    "## Executive Summary\n"
    "2–4 sentences on the real risk posture of THIS host. End with a final line, "
    "exactly: `**Overall risk:** <CRITICAL|HIGH|MEDIUM|LOW>`\n\n"
    "## Key Findings\n"
    "A Markdown table, highest priority first (KEV/high-EPSS/probe-confirmed at top). "
    "Columns EXACTLY:\n"
    "`| Severity | Finding | Port/Service | CVE(s) | Confidence | EPSS | Evidence |`\n"
    "Severity ∈ CRITICAL|HIGH|MEDIUM|LOW. Confidence ∈ Confirmed|Likely|Potential "
    "(Confirmed = probe-verified or authenticated ground truth; Likely = "
    "version-CONFIRMED match with a credible precondition; Potential = unverified "
    "lead). EPSS = the number from the data (or `—`). Evidence = the specific scan "
    "fact (banner/version/precondition/exposed file). One row per finding. If there "
    "are none, write exactly: `_No credible findings from the current evidence._`\n\n"
    "## Attack Chains\n"
    "Zero or more chains. Each chain MUST use this EXACT template (no deviations):\n"
    "### Chain <N> — <short title> `[<SEVERITY>]` `[<CONFIDENCE>]`\n"
    "- **Objective:** <attacker goal>\n"
    "- **Entry point:** <port/service/version>\n"
    "- **Steps:**\n"
    "  1. <concrete action> — exploit `<CVE-ID or precondition>` → <result> _(evidence: <scan fact>)_\n"
    "  2. <next step> …\n"
    "- **Prerequisites:** <conditions that must hold for this to work>\n"
    "- **Impact:** <what the attacker gains>\n"
    "- **Breaks if:** <the single control/patch that defeats this chain>\n"
    "A step may exploit a CVE OR a NON-CVE weakness (a misconfiguration, an exposed "
    "interface, an info leak, a benign fact made dangerous by combination). EVERY step "
    "must cite a concrete fact from the scan data in the _(evidence: …)_ tag — never "
    "invent the underlying fact. Only present a chain whose entry point and each step "
    "are supported by the evidence; prefer one well-grounded chain over several "
    "speculative ones. If no credible multi-step chain exists, output exactly this "
    "line and nothing else in the section: "
    "`_No credible multi-step attack chain from the current evidence._`\n\n"
    "## Beyond Known CVEs\n"
    "The analyst-grade section: weaknesses and risks NOT captured by a CVE match. "
    "Cover (only where the evidence supports it) — exposed/attackable surface, "
    "end-of-life or unmaintained software, dangerous defaults, information disclosure, "
    "and plausible UNDISCOVERED vulnerability classes for this specific stack. Format as "
    "a bullet list; tag each item with its kind in backticks:\n"
    "`[Exposure]` `[EOL]` `[Design]` `[Info-leak]` `[Hypothesis]`\n"
    "Each bullet: **<weakness>** `[<kind>]` — why it is a risk for THIS host, grounded "
    "in a specific scan fact, even though no CVE flags it. A `[Hypothesis]` item is an "
    "UNVERIFIED informed prediction (e.g. \"EOL `nginx 1.14` likely carries undisclosed "
    "bugs; no upstream fixes since 2019\") — phrase it as a hypothesis to validate, never "
    "as a confirmed vulnerability, and never attach a fabricated CVE ID. If the host "
    "genuinely presents no surface beyond the CVEs above, write exactly: `_No additional "
    "attack surface beyond the findings above._`\n\n"
    "## False Positives & Noise\n"
    "Bullet list: each POTENTIAL/low-EPSS lead you are de-prioritizing and the "
    "one-line reason (patched, backported, coarse version, auth-gated, edge-not-origin). "
    "If none, write `_None._`\n\n"
    "## Remediation\n"
    "Bullet list ordered to match Key Findings. Each: `**<fix>**` — <concrete action> "
    "(and, where useful, the exact follow-up probe to CONFIRM the finding).\n\n"
    "═══ RULES ═══\n"
    "Never present invented ports, services, versions, or CVE IDs as FACT, and never "
    "fabricate a CVE identifier. Facts (Key Findings, Attack-Chain evidence) must be "
    "grounded in the provided data. You MAY, however, reason beyond the data in the "
    "'Beyond Known CVEs' section and in chain analysis — provided such reasoning is "
    "clearly labeled a `[Hypothesis]`/prediction and built on an observed fact (e.g. an "
    "EOL version, an exposed interface), not pulled from thin air. Keep the distinction "
    "sharp: the Key Findings table is for what the evidence supports; hypotheses and "
    "emergent risks live in their own section so they never masquerade as confirmed. "
    "Use `inline code` for ports, versions, CVE IDs, and file paths. Prefer a correct, "
    "well-grounded assessment over an exhaustive speculative one — but do NOT stay "
    "silent about a real risk just because no CVE names it. Do not restate the raw "
    "JSON; interpret it."
)


def _build_messages(findings: dict) -> list[dict]:
    user = (
        "Analyze this authorized NetLogic scan and write the report, following the "
        "OUTPUT CONTRACT exactly (the six `##` sections, the Key Findings table "
        "columns, and the Attack Chains template). Ground factual claims in the JSON "
        "below and cite the specific fact as evidence — but also do the analyst work in "
        "'Beyond Known CVEs': call out non-CVE exposure, end-of-life/undiscovered-class "
        "risk (as labeled hypotheses), and emergent risks from chaining benign facts.\n\n"
        "```json\n" + json.dumps(findings, indent=2, default=str) + "\n```"
    )
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


# ─── HTTP transport (stdlib) ──────────────────────────────────────────────────

def _http_post(url: str, headers: dict, payload: dict, timeout: float) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = resp.status
        body = resp.read().decode("utf-8")
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"Non-JSON response from {url}: HTTP {status} — {body[:500]!r}"
        ) from e


def _raise_if_error_body(body: dict, cfg: AIConfig) -> None:
    """Raise on an OpenAI/Anthropic-style {"error": ...} body returned with HTTP 200.

    Transient upstream failures (504 etc.) raise _TransientAIError so analyze()
    retries; anything else raises RuntimeError with a clear, attributed message.
    """
    err = body.get("error") if isinstance(body, dict) else None
    if not err:
        return
    if isinstance(err, dict):
        msg = err.get("message") or json.dumps(err)
        raw_code = err.get("code")
    else:
        msg, raw_code = str(err), None
    try:
        code = int(raw_code)
    except (TypeError, ValueError):
        code = None
    label = f"{cfg.provider} upstream error" + (f" {code}" if code else "")
    if code in _RETRYABLE_STATUS:
        raise _TransientAIError(f"{label}: {msg}", status=code)
    raise RuntimeError(f"{label}: {msg}")


def _call_openai(cfg: AIConfig, messages: list[dict]) -> AIAnalysis:
    url = cfg.base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Content-Type": "application/json",
    }
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    if cfg.provider == "openrouter":
        # Optional but recommended attribution headers for OpenRouter.
        headers["HTTP-Referer"] = "https://github.com/netlogic"
        headers["X-Title"] = "NetLogic"
    payload = {
        "model": cfg.model,
        "messages": messages,
        "temperature": cfg.temperature,
        "max_tokens": cfg.max_tokens,
    }
    body = _http_post(url, headers, payload, cfg.timeout)
    # OpenAI-compatible providers (notably OpenRouter) return HTTP 200 with an
    # {"error": {...}} body when the upstream model backend fails — e.g. a 504
    # gateway timeout. Surface that clearly, and mark transient ones for retry.
    _raise_if_error_body(body, cfg)
    choices = body.get("choices") or []
    if not choices:
        return AIAnalysis(error=f"Empty response from {cfg.provider}: {json.dumps(body)[:300]}",
                          model=cfg.model, provider=cfg.provider)
    text = (choices[0].get("message") or {}).get("content", "")
    finish_reason = choices[0].get("finish_reason")
    if finish_reason == "length":
        text += (
            "\n\n> ⚠️ **AI analysis was truncated** — the model hit its token limit "
            f"({cfg.max_tokens}). Some findings may be incomplete. "
            "Consider increasing `max_tokens` or splitting the scan."
        )
    usage = body.get("usage") or {}
    return AIAnalysis(markdown=text.strip(), model=cfg.model, provider=cfg.provider,
                      tokens=usage.get("total_tokens"))


def _call_anthropic(cfg: AIConfig, messages: list[dict]) -> AIAnalysis:
    url = cfg.base_url.rstrip("/") + "/v1/messages"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": cfg.api_key,
        "anthropic-version": "2023-06-01",
    }
    system = next((m["content"] for m in messages if m["role"] == "system"), "")
    chat = [m for m in messages if m["role"] != "system"]
    payload = {
        "model": cfg.model,
        "system": system,
        "messages": chat,
        "max_tokens": cfg.max_tokens,
        "temperature": cfg.temperature,
    }
    body = _http_post(url, headers, payload, cfg.timeout)
    _raise_if_error_body(body, cfg)
    blocks = body.get("content") or []
    text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    if not text:
        return AIAnalysis(error=f"Empty response from anthropic: {json.dumps(body)[:300]}",
                          model=cfg.model, provider=cfg.provider)
    if body.get("stop_reason") == "max_tokens":
        text += (
            "\n\n> ⚠️ **AI analysis was truncated** — the model hit its token limit "
            f"({cfg.max_tokens}). Some findings may be incomplete. "
            "Consider increasing `max_tokens` or splitting the scan."
        )
    usage = body.get("usage") or {}
    total = (usage.get("input_tokens", 0) + usage.get("output_tokens", 0)) or None
    return AIAnalysis(markdown=text.strip(), model=cfg.model, provider=cfg.provider, tokens=total)


# ─── Public entry point ───────────────────────────────────────────────────────

def analyze(findings: dict, cfg: AIConfig) -> AIAnalysis:
    """Send findings to the configured LLM and return an AIAnalysis (fail-soft)."""
    usable, reason = cfg.is_usable()
    if not usable:
        return AIAnalysis(error=reason, model=cfg.model or "", provider=cfg.provider)

    messages = _build_messages(findings)

    def _once() -> AIAnalysis:
        if cfg.api_style == "anthropic":
            return _call_anthropic(cfg, messages)
        return _call_openai(cfg, messages)

    last_transient = ""
    for attempt in range(_MAX_AI_ATTEMPTS):
        try:
            return _once()
        except _TransientAIError as e:
            last_transient = str(e)
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", errors="replace")[:400]
            except Exception:
                pass
            if e.code in _RETRYABLE_STATUS:
                last_transient = f"HTTP {e.code} from {cfg.provider}: {detail}"
            else:
                return AIAnalysis(error=f"HTTP {e.code} from {cfg.provider}: {detail}",
                                  model=cfg.model, provider=cfg.provider)
        except urllib.error.URLError as e:
            # Connection/timeout blips are transient — worth a retry.
            last_transient = f"Network error reaching {cfg.provider}: {e.reason}"
        except Exception as e:  # noqa: BLE001 - fail-soft by design
            return AIAnalysis(error=f"AI analysis failed: {type(e).__name__}: {e}",
                              model=cfg.model, provider=cfg.provider)

        # Transient failure — back off and retry unless this was the last attempt.
        if attempt < _MAX_AI_ATTEMPTS - 1:
            time.sleep(_RETRY_BACKOFF_SECONDS[min(attempt, len(_RETRY_BACKOFF_SECONDS) - 1)])

    return AIAnalysis(
        error=(f"{last_transient} — retried {_MAX_AI_ATTEMPTS}× without success. "
               "This is an upstream provider timeout/overload, not a scan failure; "
               "try again shortly or switch to a faster/more-available model in Settings."),
        model=cfg.model, provider=cfg.provider,
    )


def analyze_scan(host_result, vuln_matches=None, cfg: Optional[AIConfig] = None,
                 **finding_kwargs) -> AIAnalysis:
    """Convenience wrapper: summarize a scan and analyze it in one call."""
    cfg = cfg or config_from_env()
    findings = summarize_findings(host_result, vuln_matches, **finding_kwargs)
    return analyze(findings, cfg)
