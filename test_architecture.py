"""Architecture Summary — synthesise scattered observations into one coherent picture (deterministic)."""
from src.architecture import summarize_architecture


def _zipenvy_art():
    """A zipenvy-like artifact: Vercel + Cloudflare + React SPA + Clerk + Supabase, no server."""
    return {
        "web_fingerprint": {
            "frontend": "React SPA", "is_spa": True,
            "js_endpoints": ["/api/broadcast", "/api/saved-locations"], "exposed_files": [],
            "saas": [
                {"service": "Clerk", "category": "auth", "evidence": "helped-alpaca-45", "severity": "MEDIUM"},
                {"service": "Supabase", "category": "backend", "evidence": "xuqi.supabase.co", "severity": "LOW"},
            ],
        },
        "stack_result": {
            "technologies": [{"category": "CDN", "name": "Cloudflare", "evidence": "cf-ray"}],
            "hosting": "Vercel", "cloud_provider": None, "cdn": "Cloudflare",
            "waf": {"detected": False},
        },
        "header_audit": {"server_banner": "Vercel", "powered_by": None},
        "topology": {"asn_org": "Cloudflare, Inc.", "asn": "AS13335"},
        "dns_result": {"mx_records": [{"provider": "Google Workspace"}], "email_spoofable": True},
        "tls_results": [{"port": 443}],
        "host_result": {"ports": [{"port": 443, "service": "https"}, {"port": 80, "service": "http"}]},
    }


def test_serverless_spa_is_recognised():
    a = summarize_architecture(_zipenvy_art())
    assert a is not None
    assert a.stack_kind == "serverless-spa"           # SPA + SaaS backend, no server framework


def test_narrative_reads_like_the_target_example():
    a = summarize_architecture(_zipenvy_art())
    n = a.narrative
    assert "React SPA" in n
    assert "Vercel" in n and ("Cloudflare" in n)
    assert "Clerk" in n and "Supabase" in n
    assert "serverless" in n.lower()
    assert "attack surface" in n.lower()


def test_attack_surfaces_are_derived_deterministically():
    a = summarize_architecture(_zipenvy_art())
    s = " · ".join(a.attack_surfaces).lower()
    assert "client-side bundle" in s
    assert "authentication" in s
    assert "api endpoint" in s
    assert "row-level security" in s or "supabase" in s
    assert "email spoofing" in s                       # dns email_spoofable=True


def test_components_carry_roles_evidence_and_confidence():
    a = summarize_architecture(_zipenvy_art())
    roles = {c.role for c in a.components}
    assert {"frontend", "auth", "backend"} <= roles
    assert any(c.role == "auth" and c.name == "Clerk" for c in a.components)
    d = a.to_dict()
    assert set(d) == {"narrative", "stack_kind", "execution_model", "components", "attack_surfaces"}
    assert d["components"][0].keys() >= {"role", "name", "evidence", "confidence"}
    # deterministic confidence: an explicit Server header (Vercel) = 100; a SaaS bundle ref = 96
    assert any(c.name == "Vercel" and c.confidence == 100 for c in a.components)
    assert any(c.name == "Clerk" and c.confidence >= 95 for c in a.components)


def test_execution_model_is_surfaced():
    a = summarize_architecture(_zipenvy_art())
    assert a.execution_model == "Serverless"


def test_traditional_server_stack_kind():
    art = {"stack_result": {"technologies": [
        {"category": "Server", "name": "nginx", "evidence": "Server header"},
        {"category": "Language", "name": "PHP", "evidence": "x-powered-by"},
    ]}}
    a = summarize_architecture(art)
    assert a.stack_kind == "traditional-server"
    assert "nginx" in a.narrative


def test_nothing_known_returns_none():
    assert summarize_architecture({}) is None
    assert summarize_architecture({"host_result": {"ports": []}}) is None
