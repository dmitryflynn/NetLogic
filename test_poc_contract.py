"""PoC contract + open-redirect host checks for executive/synthesis reports."""
from src.fusion.synthesis import ensure_findings_have_poc
from src.vuln_prober import is_external_open_redirect, http_poc, CVEProbe, ensure_probe_poc


def test_ensure_findings_have_poc_injects_when_missing():
    md = """## Executive Summary
Risk is medium.
**Overall risk:** MEDIUM

## Findings
### 1. CWE-601 Open Redirect `[MEDIUM]` `[Confirmed]`
- **What:** open redirect
- **Technical detail:** Location controlled
- **Remediation:** allowlist

## Attack Chains
_No multi-step_

## Beyond Known CVEs
_None._

## False Positives & Noise
_None._

## Remediation
- fix it
"""
    ctx = {
        "host": "evil.example",
        "confirmed_vulns": [{
            "cve": "CWE-601",
            "title": "CWE-601 Open Redirect",
            "poc": {
                "curl": "curl -sk 'https://evil.example/?url=https://x.invalid'",
                "expected": "Location host = x.invalid",
            },
        }],
    }
    out = ensure_findings_have_poc(md, context=ctx)
    assert "Proof of concept" in out or "How to reproduce" in out
    assert "curl -sk" in out
    assert "Location host = x.invalid" in out


def test_ensure_findings_skips_when_poc_present():
    md = """## Findings
### 1. TLS Weak Cipher `[LOW]` `[Likely]`
- **What:** weak cipher
- **Technical detail:** RC4
- **Proof of concept:**
```
openssl s_client -connect h:443
```
- **Remediation:** disable RC4

## Attack Chains
_No_
"""
    out = ensure_findings_have_poc(md, context={"host": "h"})
    # Should not duplicate PoC section
    assert out.count("Proof of concept") == 1


def test_http_poc_and_ensure_probe_poc():
    p = CVEProbe(
        cve_id="CWE-548", title="Listing", severity="LOW", confirmed=True,
        detail="dir listing", evidence="GET /uploads/ → HTTP 200 Index of",
    )
    ensure_probe_poc(p, "t.com", 443, "https")
    assert p.poc["curl"].startswith("curl")
    assert "/uploads/" in p.poc["curl"]
    assert "t.com" in p.poc["curl"]


def test_is_external_open_redirect_marker_in_query_fp():
    m = "netlogic-redirect-test.invalid"
    assert not is_external_open_redirect(
        f"https://zipenvy.com/?url=https://{m}", "zipenvy.com", m
    )
    assert is_external_open_redirect(f"https://{m}/", "zipenvy.com", m)
