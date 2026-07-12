"""SaaS / third-party backend detection from a JS bundle — WS6 modern-web surface.

The point is CORRECT severity: publishable/anon keys are public BY DESIGN (INFO/LOW), a
secret key (sk_, service_role, private key) is a real leak (CRITICAL). Being smarter than
a naive 'any key = HIGH' scanner is the differentiator.
"""
import base64

from src.web_fingerprint import detect_saas


def _sev(hits, service):
    return {h.severity for h in hits if h.service == service}


def test_clerk_test_key_is_medium_not_high():
    # a real zipenvy-style Clerk test publishable key (base64 instance)
    inst = base64.b64encode(b"helped-alpaca-45.clerk.accounts.dev$").decode()
    blob = f'clerkPublishableKey:"pk_test_{inst}",clerk.accounts.dev'
    hits = detect_saas(blob)
    clerk = [h for h in hits if h.service == "Clerk"]
    assert clerk and any(h.severity == "MEDIUM" for h in clerk)   # test-instance-in-prod, NOT HIGH
    # the instance was decoded from base64 as evidence
    assert any("helped-alpaca-45" in h.evidence for h in clerk)


def test_clerk_live_key_is_info_not_a_leak():
    hits = detect_saas('pk_live_bG9uZ2xpdmVkcHJvZHVjdGlvbmtleTEyMw==')
    assert _sev(hits, "Clerk") == {"INFO"}       # publishable — public by design, don't cry wolf


def test_supabase_project_ref_is_low_with_rls_note():
    hits = detect_saas('url:"https://xuqixapsunixvabkewjb.supabase.co/rest/v1"')
    sb = [h for h in hits if h.service == "Supabase"]
    assert sb and sb[0].severity == "LOW"
    assert "RLS" in sb[0].detail or "Row-Level" in sb[0].detail


def test_supabase_service_role_jwt_is_critical():
    payload = base64.urlsafe_b64encode(b'{"role":"service_role","iss":"supabase"}').decode().rstrip("=")
    jwt = f"eyJhbGciOiJIUzI1NiI.{payload}.c2lnbmF0dXJlZGF0YQ"
    hits = detect_saas(f'const KEY="{jwt}"')
    assert any(h.service == "Supabase" and h.severity == "CRITICAL" for h in hits)


def test_stripe_secret_key_is_critical_publishable_is_info():
    # fake secret assembled from parts so no live-looking `sk_live_...` literal is committed
    # (GitHub push-protection blocks such literals); the runtime string is unchanged.
    sk = "sk_live_" + "51ABCdefGHIjklMNOpqrstuvwx"
    hits = detect_saas(f'stripe pk_live_51ABCdefGHIjklMNOpqrs uses {sk}')
    stripe = {h.severity for h in hits if h.service == "Stripe"}
    assert "CRITICAL" in stripe        # the sk_ secret key
    assert "INFO" in stripe            # the pk_ publishable key


def test_firebase_apikey_is_info_by_design():
    hits = detect_saas('firebaseConfig={apiKey:"AIzaSyD1234567890abcdefghijklmnopqrstuv"}')
    assert _sev(hits, "Firebase") == {"INFO"}


def test_aws_key_and_private_key_are_hard_secrets():
    hits = detect_saas("AKIAIOSFODNN7EXAMPLE\n-----BEGIN RSA PRIVATE KEY-----\nx\n")
    assert any(h.service == "AWS" and h.severity == "HIGH" for h in hits)
    assert any(h.service == "Private key" and h.severity == "CRITICAL" for h in hits)


def test_clean_bundle_yields_nothing():
    assert detect_saas("function add(a,b){return a+b}") == []


def test_dedup_across_repeats():
    blob = "clerk.accounts.dev " * 5
    hits = detect_saas(blob)
    assert len([h for h in hits if h.service == "Clerk"]) == 1


def test_waf_challenge_helpers():
    from src.web_fingerprint import _WAF_CHALLENGE_RE, _waf_vendor
    vercel = "<title>Vercel Security Checkpoint</title> x-vercel-mitigated: challenge"
    assert _WAF_CHALLENGE_RE.search(vercel) and _waf_vendor(vercel) == "Vercel"
    assert _WAF_CHALLENGE_RE.search("Attention Required! Cloudflare __cf_chl")
    assert _waf_vendor("checking your browser cloudflare") == "Cloudflare"
    assert not _WAF_CHALLENGE_RE.search("<html><div id='root'></div></html>")


def test_architecture_surfaces_waf():
    from src.architecture import summarize_architecture
    a = summarize_architecture({"web_fingerprint": {"waf": "Vercel"},
                                "header_audit": {"server_banner": "Vercel"}})
    assert a is not None
    assert any(c.role == "waf" and "Vercel" in c.name for c in a.components)
