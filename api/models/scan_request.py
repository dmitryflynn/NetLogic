"""
NetLogic API — Scan request model.

Mirrors the CLI flags accepted by netlogic.py / run_streaming_scan() with
full Pydantic v2 validation.  All fields are optional except `target`.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# RFC 1123 label: 1-63 chars, starts/ends with alnum, may contain hyphens.
_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


class ScanRequest(BaseModel):
    # ── Required ─────────────────────────────────────────────────────────────
    target: str = Field(
        ...,
        description=(
            "Hostname, IP address, or CIDR range to scan "
            "(e.g. 'example.com', '10.0.0.5', '192.168.1.0/24')."
        ),
    )

    # ── Port selection ────────────────────────────────────────────────────────
    ports: str = Field(
        "quick",
        description=(
            "'quick' (43 ports), 'full' (58 ports), "
            "or 'custom=21,22,80,443' for an explicit list."
        ),
    )

    # ── Scan modules ─────────────────────────────────────────────────────────
    do_tls: bool = Field(False, description="Deep SSL/TLS analysis.")
    do_headers: bool = Field(False, description="HTTP security header audit.")
    do_stack: bool = Field(False, description="Technology stack + WAF fingerprinting.")
    do_dns: bool = Field(False, description="DNS / email security (SPF, DKIM, DMARC, DNSSEC).")
    do_osint: bool = Field(False, description="Passive OSINT recon.")
    do_probe: bool = Field(False, description="Active service probing (misconfigs, default creds, CVE checks).")
    do_takeover: bool = Field(False, description="Subdomain takeover detection.")
    do_full: bool = Field(False, description="Enable ALL scan modules (overrides individual flags).")

    # ── CIDR mode ────────────────────────────────────────────────────────────
    cidr: bool = Field(False, description="Treat target as a CIDR block and scan every host.")

    # ── Tuning ───────────────────────────────────────────────────────────────
    timeout: float = Field(
        2.0, ge=0.5, le=30.0,
        description="Per-port TCP connect timeout in seconds.",
    )
    threads: int = Field(
        100, ge=1, le=500,
        description="Thread-pool size for parallel port scanning.",
    )
    min_cvss: float = Field(
        4.0, ge=0.0, le=10.0,
        description="Minimum CVSS score to include in CVE findings.",
    )
    nvd_key: str = Field(
        "",
        description="Optional NVD API key for higher rate limits.",
    )

    # ── Agent routing ─────────────────────────────────────────────────────────
    agent_id: Optional[str] = Field(
        None,
        description=(
            "ID of a registered remote agent to run this scan. "
            "If omitted the scan executes locally on the controller (Phase 1 behaviour). "
            "If set, the job is queued in the agent's task list and will run "
            "on the agent's local network when the agent next polls."
        ),
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Validators
    # ─────────────────────────────────────────────────────────────────────────

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target cannot be empty")
        if len(v) > 253:
            raise ValueError("target too long — maximum 253 characters")

        # Try plain IPv4 / IPv6 address first.
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass

        # Try CIDR notation (IPv4 or IPv6).
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            pass

        # Validate as an RFC 1123 hostname (allows sub-domains).
        labels = v.rstrip(".").split(".")
        for label in labels:
            if not label:
                raise ValueError("invalid target: empty label in hostname")
            if len(label) > 63:
                raise ValueError(f"invalid target: label '{label[:20]}…' exceeds 63 characters")
            if not _LABEL_RE.match(label):
                raise ValueError(
                    f"invalid target: label '{label[:20]}' contains invalid characters"
                )
        return v

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, v: str) -> str:
        if v in ("quick", "full"):
            return v

        raw = v[len("custom="):] if v.startswith("custom=") else v
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if not parts:
            raise ValueError("ports list is empty")

        for p in parts:
            if not p.isdigit():
                raise ValueError(
                    f"invalid port '{p}' — must be a positive integer"
                )
            port_num = int(p)
            if not 1 <= port_num <= 65535:
                raise ValueError(f"port {port_num} is out of range (1–65535)")

        # Normalise to the canonical 'custom=...' form so the executor doesn't
        # need to handle the bare comma-separated case.
        if not v.startswith("custom="):
            return "custom=" + ",".join(parts)
        return v

    @model_validator(mode="after")
    def _validate_cidr_with_target(self) -> "ScanRequest":
        """When cidr=True the target must look like a CIDR block."""
        if self.cidr and "/" not in self.target:
            raise ValueError(
                "cidr=true requires target to be a CIDR block (e.g. '192.168.1.0/24')"
            )
        return self

    # ─────────────────────────────────────────────────────────────────────────
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "target": "scanme.nmap.org",
                    "ports": "quick",
                    "timeout": 2.0,
                    "threads": 100,
                },
                {
                    "target": "example.com",
                    "ports": "full",
                    "do_tls": True,
                    "do_headers": True,
                    "do_dns": True,
                    "timeout": 3.0,
                },
                {
                    "target": "192.168.1.0/24",
                    "cidr": True,
                    "ports": "quick",
                    "timeout": 1.0,
                    "threads": 200,
                },
            ]
        }
    }
