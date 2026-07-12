"""Evidence grounding — synthesis must not invent Confirmed/PoCs."""
from src.fusion.synthesis import (
    build_repro_ledger,
    allowed_confirmed_subjects,
    ground_synthesis_markdown,
)
from src.fusion.gate import Verdict


def test_ledger_captures_observed_location():
    ctx = {
        "host": "zipenvy.com",
        "ai_agent": {
            "observations": [{
                "observation_id": "obs_1",
                "tool": "http_proof",
                "summary": "PROOF GET /api/auth/callback → HTTP 307",
                "data": {
                    "path": "/api/auth/callback?callbackUrl=https://evil.com",
                    "method": "GET",
                    "status": 307,
                    "location": "https://www.zipenvy.com/api/auth/callback?callbackUrl=https://evil.com",
                    "location_host": "www.zipenvy.com",
                    "open_redirect_signal": False,
                    "proof_signals": ["same_site_redirect", "marker_echoed_in_same_site_location_query"],
                    "vulnerable_signal": False,
                    "observed_summary": "HTTP 307; Location: https://www.zipenvy.com/...",
                },
            }],
            "findings": [],
            "pocs": [],
        },
    }
    ledger = build_repro_ledger(ctx)
    assert ledger
    assert ledger[0]["location_host"] == "www.zipenvy.com"
    assert ledger[0]["open_redirect_signal"] is False
    assert "evil.com" in (ledger[0].get("location") or "")
    assert "www.zipenvy.com" in (ledger[0].get("location") or "")


def test_grounding_demotes_invented_confirmed_and_evil_location():
    ctx = {
        "host": "zipenvy.com",
        "ai_agent": {
            "observations": [{
                "observation_id": "obs_1",
                "tool": "http_proof",
                "summary": "same site",
                "data": {
                    "path": "/api/auth/callback?callbackUrl=https://evil.com",
                    "status": 307,
                    "location": "https://www.zipenvy.com/api/auth/callback?callbackUrl=https://evil.com",
                    "location_host": "www.zipenvy.com",
                    "open_redirect_signal": False,
                    "proof_signals": ["same_site_redirect"],
                    "vulnerable_signal": False,
                },
            }],
            "findings": [],  # nothing confirmed
        },
    }
    md = """## Executive Summary
Risk low.
**Overall risk:** LOW

## Findings
### 1. Open Redirect in Auth `[HIGH]` `[Confirmed]`
- **What:** Unvalidated redirect
- **Technical detail:** callbackUrl reflected
- **Proof of concept / How to reproduce:**
```
curl -v "https://zipenvy.com/api/auth/callback?callbackUrl=https://evil.com"
```
A vulnerable response will return Location: https://evil.com
- **Remediation:** allowlist

## Attack Chains
_No_

## Beyond Known CVEs
_None._

## False Positives & Noise
_None._

## Remediation
- fix
"""
    out = ground_synthesis_markdown(md, context=ctx, confirmed=[])
    assert "`[Potential]`" in out or "[Potential]" in out
    assert "evil.com" not in out.split("Location:")[1][:80] if "Location:" in out else True
    assert "evidence gate" in out.lower()
    # Invented Confirmed should not stand
    # (may still have the word Confirmed in the demotion note — check tag)
    assert not re_search_confirmed_tag_on_header(out)


def re_search_confirmed_tag_on_header(md: str) -> bool:
    for line in md.splitlines():
        if line.strip().startswith("### ") and "Confirmed" in line and "Potential" not in line:
            return True
    return False


def test_allowed_confirmed_from_agent_only():
    ctx = {
        "ai_agent": {
            "findings": [
                {"id": "cve-2021-31166", "title": "http.sys", "status": "confirmed"},
                {"id": "open-redirect", "title": "OR", "status": "lead"},
            ],
        },
    }
    allowed = allowed_confirmed_subjects([], ctx)
    assert any("31166" in a.lower() for a in allowed)
    assert not any("open-redirect" == a.lower() for a in allowed)
