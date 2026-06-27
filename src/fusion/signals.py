"""
Fusion layer — the Signal schema.

A Signal is one evidence-bearing observation from a sensor (a Nuclei match, a
Wappalyzer hit, a probe result, a banner, an NVD/OSV correlation, a BYOK-EASM
lookup). Everything downstream hangs off this contract, so it carries:

  • provenance      — which sensor, and that sensor's inherent reliability,
  • raw evidence    — the actual observed fact the AI reasons over (not a verdict),
  • deterministic impact inputs — KEV/CVSS/EPSS/exploit (NOT a sensor's self-declared
                      "severity" label, which is stripped to fight LLM trigger-word bias),
  • exposure        — reachability/network-position, the edge data for the attack graph.

`ai_view()` is the deliberately-reduced representation handed to an LLM: the tool
NAME and any self-declared severity are removed so the model judges the bytes, not
the brand. Audit/`raw_metadata` is retained server-side but never sent to the model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# Inherent reliability of a sensor's signal — how much a *single* such signal is
# worth before corroboration. Probes that elicit a distinctive response are high;
# banner/version guesses are low; pattern matches are medium.
RELIABILITY_TIERS = ("high", "medium", "low")

# Sensor identifiers. Independence for the agreement gate is counted across these.
SOURCES = ("probe", "banner", "nuclei", "wappalyzer", "nvd", "osv", "easm", "tls", "dns")

_MAX_EVIDENCE = 600  # cap evidence bytes shown to the AI / stored per signal


@dataclass
class Signal:
    source: str                 # one of SOURCES — the sensor that produced this
    kind: str                   # "vuln" | "tech" | "exposure" | "misconfig" | "service"
    claim: str                  # normalized subject, e.g. "jenkins", "CVE-2021-44228"
    host: str
    port: Optional[int] = None
    service: str = ""

    evidence: str = ""          # the raw observed fact/bytes that triggered this signal
    confidence: float = 0.5     # the sensor's own confidence in THIS match, 0..1
    reliability: str = "medium" # inherent reliability of this sensor's signal

    # ── Deterministic impact inputs (NOT a self-declared severity label) ──────────
    kev: bool = False               # CISA Known Exploited — actively exploited
    epss: float = 0.0               # P(exploited in 30d), 0..1
    cvss: float = 0.0               # base score, 0..10
    exploit_available: bool = False # public exploit / Metasploit module exists
    version_matched: bool = False   # detected by version/banner content, not active probe —
                                    # prevents auto-pinning by EPSS/exploit alone; the
                                    # finding must remain candidate for patch-level verification.
    probe_confirmed: bool = False   # actively verified via an exploit/evidence probe (not
                                    # just a version/banner match) — pins findings through
                                    # the gate as ground truth regardless of sensor source.

    # ── Exposure / reachability — first-class edge data for the attack graph ──────
    # {"reachability": "public"|"private"|"cloud"|"unknown", "waf": <name|None>,
    #  "vantage": <agent_id|None>}
    exposure: Optional[dict] = None

    # ── Raw observation data — the actual bytes the sensor saw (sent to the AI) ────
    # Structured snapshot of what the sensor observed that triggered this signal.
    # Content varies by sensor (HTTP response for nuclei, banner for nvd, probe
    # interaction for probe sensors). Body text is capped at 500 chars. Sensor names
    # and severity labels are NEVER included.
    observed_data: Optional[dict] = None

    # ── Audit only — NEVER sent to the AI ─────────────────────────────────────────
    raw_metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.reliability not in RELIABILITY_TIERS:
            self.reliability = "medium"
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        if self.evidence and len(self.evidence) > _MAX_EVIDENCE:
            self.evidence = self.evidence[:_MAX_EVIDENCE] + "…[truncated]"

    @property
    def is_probe_confirmed(self) -> bool:
        """A high-reliability probe directly elicited the evidence (ground truth-ish).

        Returns True if either:
        1. A ``probe`` sensor with high reliability (legacy path), or
        2. The ``probe_confirmed`` field is explicitly set (verifier path).
        """
        return (self.source == "probe" and self.reliability == "high") or self.probe_confirmed

    def ai_view(self) -> dict:
        """Reduced, label-stripped view for an LLM.

        Removes the sensor NAME, every self-declared severity/score, and audit-only
        `raw_metadata` so the model evaluates the observed evidence and exposure, not
        scary software names or a tool's pre-baked verdict. The subject (claim) is kept
        but must be treated by the prompt as an UNVERIFIED label.

        `observed_data` IS included (it carries the raw bytes/headers the sensor saw)
        but body text values inside it are truncated to prevent token explosion.
        """
        data = self.observed_data
        if data is not None:
            # Deep-copy and cap body content; we never mutate the original.
            data = {k: v for k, v in data.items()}
            for key in ("body", "body_snippet", "response_body"):
                if isinstance(data.get(key), str) and len(data[key]) > 500:
                    data[key] = data[key][:500] + "…[truncated]"
            if isinstance(data.get("headers"), dict):
                data["headers"] = dict(data["headers"])
        return {
            "kind": self.kind,
            "subject": self.claim,
            "port": self.port,
            "service": self.service or None,
            "evidence": self.evidence or None,
            "observed_data": data,
            "exposure": self.exposure or {"reachability": "unknown"},
        }

    def subject_key(self) -> tuple:
        """Identity of the *thing* being asserted, for grouping/corroboration."""
        return (self.host, self.port, self.claim.lower().strip())
