"""
Architecture Summary — synthesise scattered observations into ONE coherent picture.

NetLogic already sees the pieces (React, Vercel, Cloudflare, Clerk, Supabase, TLS, DNS, endpoints,
CVEs) — but a list of observations makes the reader do the assembly. This turns them into a plain-
English "here is what this application IS and where its real attack surface lives", which is useful
even when zero vulnerabilities are found — and gives the AI overlay a structured architecture to
reason over instead of raw facts.

PURE + DETERMINISTIC: reads the scan artifact, invents nothing, no AI, no network. The AI later
*reasons over* this (Observed Architecture → Summary → Likely Attack Surface → Objectives), it does
not replace it.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ArchComponent:
    role: str        # frontend|hosting|cdn|waf|auth|backend|payments|analytics|monitoring|server|language|email
    name: str
    evidence: str
    confidence: int = 90     # 0–100, DETERMINISTIC (detection strength, not an AI guess)

    def to_dict(self) -> dict:
        return {"role": self.role, "name": self.name, "evidence": self.evidence,
                "confidence": self.confidence}


# stack_kind → the plain "how does its code run" line the reviewer wanted as a first-class field.
_EXEC_MODEL = {"serverless-spa": "Serverless", "traditional-server": "Server-based",
               "static": "Static", "mixed": "Mixed"}


@dataclass
class ArchitectureSummary:
    narrative: str
    stack_kind: str                          # serverless-spa | traditional-server | static | mixed | unknown
    execution_model: str = ""                # "Serverless" | "Server-based" | "Static" | "Mixed"
    components: list = field(default_factory=list)        # ArchComponent
    attack_surfaces: list = field(default_factory=list)   # str

    def to_dict(self) -> dict:
        return {"narrative": self.narrative, "stack_kind": self.stack_kind,
                "execution_model": self.execution_model,
                "components": [c.to_dict() for c in self.components],
                "attack_surfaces": list(self.attack_surfaces)}


def _get(o, name, default=None):
    if isinstance(o, dict):
        return o.get(name, default)
    return getattr(o, name, default)


# SaaS category (from web_fingerprint) → architecture role.
_CAT_ROLE = {"auth": "auth", "backend": "backend", "payments": "payments",
             "monitoring": "monitoring", "analytics": "analytics", "cloud": "cloud"}
# Stack TechFinding category → role.
_TECH_ROLE = {"cdn": "cdn", "waf": "waf", "server": "server", "language": "language",
              "framework": "server", "cms": "server", "analytics": "analytics", "cloud": "hosting"}


_STACK_CONF = {"HIGH": 95, "MEDIUM": 78, "LOW": 60}


def summarize_architecture(art) -> "ArchitectureSummary | None":
    """Aggregate the scan artifact into an ArchitectureSummary, or None if too little is known.

    Every component carries a DETERMINISTIC confidence (detection strength, not an AI guess):
    an explicit header/key match ≈100, a decoded SaaS ref ≈96, a fingerprint HIGH/MED/LOW → 95/78/60,
    an ASN-org inference ≈88, a generic-SPA fallback ≈80."""
    by_key: dict = {}         # (role, name.lower()) -> ArchComponent (keep the highest-confidence hit)

    def add(role, name, evidence, confidence):
        if not name:
            return
        key = (role, str(name).lower())
        prev = by_key.get(key)
        if prev is None or confidence > prev.confidence:
            by_key[key] = ArchComponent(role, str(name), str(evidence), int(confidence))

    wf = _get(art, "web_fingerprint")
    stack = _get(art, "stack_result")
    topo = _get(art, "topology")
    hdr = _get(art, "header_audit")
    dns = _get(art, "dns_result")

    # ── Frontend ── explicit framework markers are high-confidence; a bare SPA shell is lower.
    if wf:
        fe = _get(wf, "frontend")
        if fe:
            add("frontend", fe, "JS bundle / HTML shell", 80 if "single-page" in fe.lower() else 95)
        elif _get(wf, "is_spa"):
            add("frontend", "single-page application", "client-side routing (soft-404)", 80)
        waf = _get(wf, "waf")
        if waf:
            add("waf", f"{waf} (JS challenge)", "blocks passive page/bundle analysis", 95)

    # ── Hosting / CDN / server framework / language (from stack fingerprint) ──
    if stack:
        for t in _get(stack, "technologies", []) or []:
            cat = str(_get(t, "category", "")).lower()
            role = _TECH_ROLE.get(cat)
            if role:
                conf = _STACK_CONF.get(str(_get(t, "confidence", "HIGH")).upper(), 75)
                add(role, _get(t, "name", ""), _get(t, "evidence", "") or f"stack:{cat}", conf)
        add("hosting", _get(stack, "hosting", None), "stack fingerprint", 90)
        add("hosting", _get(stack, "cloud_provider", None), "stack fingerprint", 90)
        add("cdn", _get(stack, "cdn", None), "stack fingerprint", 90)
        waf = _get(stack, "waf")
        if waf and _get(waf, "detected"):
            add("waf", _get(waf, "name", "WAF"), _get(waf, "evidence", "") or "stack fingerprint", 85)

    # ── Hosting / CDN fallbacks from headers + topology ── the Server header is explicit → ~100.
    if hdr:
        add("hosting", _get(hdr, "server_banner", None), "Server header", 100)
        pb = _get(hdr, "powered_by", None)
        if pb:
            add("server", pb, "X-Powered-By header", 95)
    if topo and _get(topo, "asn_org"):
        add("hosting", _get(topo, "asn_org"), f"ASN {_get(topo, 'asn', '')}".strip(), 88)

    # ── Auth / backend / payments / monitoring (from web_fingerprint SaaS) ── specific bundle evidence.
    saas = _get(wf, "saas", []) if wf else []
    for h in saas or []:
        role = _CAT_ROLE.get(str(_get(h, "category", "")).lower(), "backend")
        add(role, _get(h, "service", ""), _get(h, "evidence", "") or "JS bundle", 96)

    # ── Email (from DNS MX provider) ──
    if dns:
        for mx in _get(dns, "mx_records", []) or []:
            prov = _get(mx, "provider", None)
            if prov:
                add("email", prov, "MX record", 95)
                break

    comps = list(by_key.values())
    if not comps:
        return None

    # ── Stack kind ──
    roles = {c.role for c in comps}
    has_spa = any(c.role == "frontend" for c in comps)
    has_saas_backend = any(c.role in ("auth", "backend", "payments") for c in comps)
    has_server = "server" in roles
    if has_spa and has_saas_backend and not has_server:
        stack_kind = "serverless-spa"
    elif has_server:
        stack_kind = "traditional-server"
    elif has_spa:
        stack_kind = "static"
    else:
        stack_kind = "mixed"

    surfaces = _attack_surfaces(art, comps, stack_kind)
    narrative = _narrative(comps, stack_kind, surfaces)
    # Components sorted worst-→-best confidence within role handled at render; keep insertion here.
    return ArchitectureSummary(narrative=narrative, stack_kind=stack_kind,
                               execution_model=_EXEC_MODEL.get(stack_kind, ""),
                               components=comps, attack_surfaces=surfaces)


def _by_role(comps, role):
    return [c for c in comps if c.role == role]


def _names(comps, role):
    return [c.name for c in _by_role(comps, role)]


def _attack_surfaces(art, comps, stack_kind) -> list:
    out: list = []
    wf = _get(art, "web_fingerprint")
    tls = _get(art, "tls_results")
    dns = _get(art, "dns_result")
    host = _get(art, "host_result")

    if tls:
        out.append("TLS / transport security")
    if any(c.role == "frontend" for c in comps):
        out.append("client-side bundle (source is public)")
    if _names(comps, "auth"):
        out.append("authentication flows")
    if wf and (_get(wf, "js_endpoints") or []):
        out.append("exposed API endpoints")
    if any("supabase" in c.name.lower() for c in comps):
        out.append("Supabase configuration / Row-Level Security")
    if any("firebase" in c.name.lower() for c in comps):
        out.append("Firebase security rules")
    if wf and (_get(wf, "exposed_files") or []):
        out.append("exposed files")
    if dns and _get(dns, "email_spoofable"):
        out.append("email spoofing (SPF / DMARC)")
    # non-web open ports as a network surface
    ports = _get(host, "ports", []) if host else []
    net = [str(_get(p, "port")) for p in ports
           if str(_get(p, "service", "")) not in ("http", "https", "http-alt", "https-alt")]
    if net:
        out.append("network services on port(s) " + ", ".join(net[:5]))
    return out


def _joinsentence(names) -> str:
    names = [n for n in names if n]
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + " and " + names[-1]


def _narrative(comps, stack_kind, surfaces) -> str:
    fe = _names(comps, "frontend")
    hosting = _names(comps, "hosting")
    cdn = _names(comps, "cdn")
    auth = _names(comps, "auth")
    backend = _names(comps, "backend")
    payments = _names(comps, "payments")
    server = _names(comps, "server")

    parts: list[str] = []
    lead = f"This application is a {fe[0]}" if fe else "This application"
    if hosting:
        lead += f" hosted on {_joinsentence(hosting[:2])}"
    if cdn:
        lead += f" behind {_joinsentence(cdn[:2])}"
    parts.append(lead + ".")

    if auth:
        s = f"Authentication is provided by {_joinsentence(auth)}"
        if backend:
            s += f", while {_joinsentence(backend)} appears to serve as the backend database and API layer"
        parts.append(s + ".")
    elif backend:
        parts.append(f"{_joinsentence(backend)} appears to serve as the backend database and API layer.")

    if payments:
        parts.append(f"Payments are handled by {_joinsentence(payments)}.")

    if stack_kind == "serverless-spa":
        parts.append("No traditional server framework was identified, suggesting most application "
                     "logic runs in serverless functions or the third-party backends above.")
    elif server:
        parts.append(f"Server-side technology: {_joinsentence(server)}.")

    if surfaces:
        parts.append("The primary externally reachable attack surfaces are "
                     + _joinsentence(surfaces) + ".")
    return " ".join(parts)
