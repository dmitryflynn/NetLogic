"""HTTP fetch helpers that refuse to follow redirects.

urllib.request.urlopen follows 3xx by default, including cross-host hops.
A scan of an authorized public target that returns
``Location: http://169.254.169.254/...`` (or RFC1918) would otherwise make
the agent connect to metadata or internal neighbors — the same SSRF class
already blocked for LLM URLs, SIEM, vuln_prober, takeover, and active
validation. Target-facing auditors must fail the same way: return the 3xx
as HTTPError and never fetch the redirect destination.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Optional


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Replace the default redirect handler so 3xx is surfaced, not followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise urllib.error.HTTPError(
            newurl, code, "HTTP redirects are not followed", headers, fp,
        )


def urlopen_no_redirect(
    req: urllib.request.Request,
    timeout: float,
    context: Optional[object] = None,
):
    """urlopen that never follows 3xx. Optional SSL context for CERT_NONE probes."""
    handlers: list = [NoRedirectHandler]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    return opener.open(req, timeout=timeout)
