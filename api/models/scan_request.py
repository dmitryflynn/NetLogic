"""
NetLogic API — Scan request model.

Mirrors the CLI flags accepted by netlogic.py / run_streaming_scan() with
full Pydantic v2 validation.  All fields are optional except `target`.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

# RFC 1123 label: 1-63 chars, starts/ends with alnum, may contain hyphens.
_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
_AI_PROVIDERS = {"", "openrouter", "openai", "anthropic", "kimi", "qwen", "groq", "gemini", "ollama", "custom"}


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
    do_probe: bool = Field(False, description="Active service probing (misconfigs, default creds, CVE checks) + subnet host discovery for cross-host attack chaining.")
    do_takeover: bool = Field(False, description="Subdomain takeover detection.")
    do_full: bool = Field(False, description="Enable ALL scan modules (overrides individual flags).")

    # ── AI analysis + authenticated scanning ─────────────────────────────────
    do_ai: bool = Field(False, description="AI-powered analysis + attack-chain reasoning; auto-enables deep detection.")
    ai_provider: str = Field(
        "",
        description="AI provider: openrouter, openai, anthropic, kimi, qwen, groq, ollama, or custom.",
    )
    ai_key: Optional[SecretStr] = Field(
        None,
        description="Optional per-scan AI API key. Masked in API responses and omitted from persisted job config.",
    )
    ai_model: str = Field(
        "",
        max_length=160,
        description="Optional model id. For OpenRouter, paste the exact provider/model id here.",
    )
    ai_base_url: str = Field(
        "",
        max_length=300,
        description="Optional custom OpenAI-compatible base URL.",
    )
    ssh_user: str = Field("", description="Username for authenticated SSH scan (reads real installed package versions).")
    ssh_key: str = Field("", description="SSH private key path for authenticated scanning.")
    ssh_pass: str = Field("", description="SSH password (requires sshpass; key auth preferred).")
    ssh_port: int = Field(22, ge=1, le=65535, description="SSH port for authenticated scanning.")

    # ── CIDR mode ────────────────────────────────────────────────────────────
    cidr: bool = Field(False, description="Treat target as a CIDR block and scan every host.")

    # ── Deep-probe mode (multi-agent architecture) ──────────────────────────
    deep_probe: bool = Field(
        False,
        description=(
            "Use per-service agent architecture for context-isolated probe "
            "execution. Each service receives a focused probe agent with "
            "isolated SSL/HTTP state and scoped CVE context. "
            "[Paid-plan feature]"
        ),
    )

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
            "Pin this scan to one specific agent by ID. Overrides capability/"
            "selector routing — if that agent is offline the job fails fast."
        ),
    )
    required_capabilities: list[str] = Field(
        default_factory=list,
        max_length=32,
        description=(
            "Only dispatch to an agent advertising ALL of these capabilities "
            "(e.g. ['scan', 'tls']). Empty = any capability."
        ),
    )
    agent_selector: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Vantage-point routing: only dispatch to an agent whose tags match "
            "every key=value here (e.g. {'region': 'us-east', 'network': 'corp-vpc'}). "
            "Empty = any location."
        ),
    )

    @field_validator("required_capabilities", mode="before")
    @classmethod
    def _cap_required_caps(cls, v):
        if v in (None, ""):
            return []
        if not isinstance(v, list) or len(v) > 32:
            raise ValueError("required_capabilities must be a list of at most 32 strings.")
        for c in v:
            if not isinstance(c, str) or len(c) > 64:
                raise ValueError("each capability must be a string of at most 64 chars.")
        return v

    @field_validator("agent_selector", mode="before")
    @classmethod
    def _cap_selector(cls, v):
        if v in (None, ""):
            return {}
        if not isinstance(v, dict) or len(v) > 16:
            raise ValueError("agent_selector must be a dict of at most 16 key/value pairs.")
        for k, val in v.items():
            if not isinstance(k, str) or not isinstance(val, str) or len(k) > 64 or len(val) > 64:
                raise ValueError("selector keys/values must be strings of at most 64 chars.")
        return v

    @field_validator("ai_provider")
    @classmethod
    def _validate_ai_provider(cls, v: str) -> str:
        v = (v or "").lower().strip()
        if v not in _AI_PROVIDERS:
            raise ValueError("ai_provider must be one of: openrouter, openai, anthropic, kimi, qwen, groq, ollama, custom")
        return v

    @field_validator("ai_key", mode="before")
    @classmethod
    def _empty_ai_key_to_none(cls, v):
        if v is None:
            return None
        if isinstance(v, str):
            v = v.strip()
            return v or None
        return v

    @field_validator("ai_model")
    @classmethod
    def _trim_ai_model(cls, v: str) -> str:
        return (v or "").strip()

    @field_validator("ssh_user", "ssh_key")
    @classmethod
    def _reject_ssh_option_injection(cls, v: str) -> str:
        # ssh treats any argv element starting with '-' as an option, so a value
        # like '-oProxyCommand=…' is remote code execution on the scanning agent
        # (argument injection). A real username or key path never needs a leading
        # '-' or embedded whitespace/control characters — reject those outright.
        v = (v or "").strip()
        if v and (v[0] == "-" or any(c.isspace() or ord(c) < 0x20 for c in v)):
            raise ValueError("must not start with '-' or contain whitespace/control characters")
        return v

    @field_validator("ai_base_url")
    @classmethod
    def _validate_ai_base_url(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            return ""
        if not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("ai_base_url must start with http:// or https://")

        # HTTPS is always permitted (encrypted).
        if v.startswith("https://"):
            return v.rstrip("/")

        # HTTP restricted to loopback and private IPs only.
        from urllib.parse import urlparse
        host = urlparse(v).hostname or ""
        if host not in ("localhost", "127.0.0.1", "::1"):
            try:
                addr = ipaddress.ip_address(host)
                if not (addr.is_private or addr.is_loopback):
                    raise ValueError(
                        "HTTP ai_base_url must point to localhost, 127.0.0.1, "
                        "or a private IP (e.g. 10.x.x.x, 172.16-31.x.x, 192.168.x.x)"
                    )
            except ValueError:
                raise ValueError(
                    "HTTP ai_base_url must be an IP address in a private range "
                    "or localhost; use https:// for hostnames"
                )
        return v.rstrip("/")

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
        # Reject pathologically large input before splitting: a multi-MB string of
        # duplicate ports would otherwise inflate memory/CPU (there are only 65535
        # distinct ports, so a sane request is never longer than this).
        if len(raw) > 400_000:
            raise ValueError("ports list too long")
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        if not parts:
            raise ValueError("ports list is empty")

        seen: set[int] = set()
        ordered: list[str] = []
        for p in parts:
            if not p.isdigit():
                raise ValueError(
                    f"invalid port '{p}' — must be a positive integer"
                )
            port_num = int(p)
            if not 1 <= port_num <= 65535:
                raise ValueError(f"port {port_num} is out of range (1–65535)")
            # De-duplicate: bounds the effective list at ≤65535 and stops a caller
            # from inflating the scan with repeated ports.
            if port_num not in seen:
                seen.add(port_num)
                ordered.append(str(port_num))

        # Normalise to the canonical 'custom=...' form (deduplicated) so the
        # executor never sees the bare comma-separated or duplicate-laden case.
        return "custom=" + ",".join(ordered)

    @model_validator(mode="after")
    def _validate_cidr_with_target(self) -> "ScanRequest":
        """When cidr=True the target must be a CIDR block of a bounded size."""
        if self.cidr:
            if "/" not in self.target:
                raise ValueError(
                    "cidr=true requires target to be a CIDR block (e.g. '192.168.1.0/24')"
                )
            # Bound the range: a huge CIDR (e.g. /8, /0) would enumerate
            # millions/billions of hosts and exhaust agent memory (DoS). Cap at an
            # IPv4 /16 worth of addresses. Mirrors scanner.MAX_CIDR_HOSTS.
            try:
                net = ipaddress.ip_network(self.target, strict=False)
            except ValueError:
                return self  # target validator already rejected truly malformed input
            if net.num_addresses > 65_536:
                raise ValueError(
                    f"CIDR range too large ({net.num_addresses} addresses). "
                    f"Maximum is 65536 (an IPv4 /16); scan smaller subnets."
                )
        return self

    def public_dump(self) -> dict:
        """Return API-safe config with AI secrets masked."""
        data = self.model_dump(mode="json")
        if self.ai_key:
            data["ai_key"] = "**********"
        return data

    def persisted_dump(self) -> dict:
        """Return disk-safe config; per-scan AI keys are never persisted."""
        data = self.model_dump(mode="json")
        data["ai_key"] = ""
        return data

    def task_dump(self) -> dict:
        """Return agent task config with the live per-scan AI key included."""
        data = self.model_dump(mode="json")
        if self.ai_key:
            data["ai_key"] = self.ai_key.get_secret_value()
        return data

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
