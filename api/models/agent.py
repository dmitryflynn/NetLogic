"""
NetLogic API — Agent Pydantic models.

Used by both the agent process (AgentRegistration, AgentTaskComplete)
and the controller routes (AgentRegistration, AgentTaskComplete).
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator

# Hard limits — prevent memory exhaustion and log-injection via large payloads.
_MAX_HOSTNAME_LEN  = 255
_MAX_TAG_PAIRS     = 20
_MAX_TAG_KEY_LEN   = 64
_MAX_TAG_VAL_LEN   = 64
_MAX_CAPS          = 32
_MAX_CAP_LEN       = 64
_MAX_VERSION_LEN   = 32


class AgentRegistration(BaseModel):
    """Payload sent by an agent on first startup to register with the controller."""

    hostname: str = Field(
        ...,
        max_length=_MAX_HOSTNAME_LEN,
        description="Hostname or human-readable name of the machine running the agent.",
    )
    capabilities: list[str] = Field(
        default_factory=list,
        max_length=_MAX_CAPS,
        description=(
            "Scan modules this agent supports, e.g. "
            "['scan', 'tls', 'dns', 'osint', 'probe', 'takeover']."
        ),
    )
    version: str = Field(
        "1.0.0",
        max_length=_MAX_VERSION_LEN,
        description="Agent software version string.",
    )
    tags: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Arbitrary key/value metadata for filtering/grouping agents, "
            "e.g. {'env': 'prod', 'region': 'us-east-1', 'customer': 'acme'}."
        ),
    )

    @field_validator("capabilities", mode="before")
    @classmethod
    def _cap_capabilities(cls, v: list) -> list:
        if len(v) > _MAX_CAPS:
            raise ValueError(f"Too many capabilities (max {_MAX_CAPS}).")
        for cap in v:
            if not isinstance(cap, str) or len(cap) > _MAX_CAP_LEN:
                raise ValueError(
                    f"Each capability must be a string of at most {_MAX_CAP_LEN} chars."
                )
        return v

    @field_validator("tags", mode="before")
    @classmethod
    def _cap_tags(cls, v: dict) -> dict:
        if len(v) > _MAX_TAG_PAIRS:
            raise ValueError(f"Too many tags (max {_MAX_TAG_PAIRS} key/value pairs).")
        for k, val in v.items():
            if not isinstance(k, str) or len(k) > _MAX_TAG_KEY_LEN:
                raise ValueError(f"Tag key must be a string of at most {_MAX_TAG_KEY_LEN} chars.")
            if not isinstance(val, str) or len(val) > _MAX_TAG_VAL_LEN:
                raise ValueError(
                    f"Tag value must be a string of at most {_MAX_TAG_VAL_LEN} chars."
                )
        return v

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "hostname": "agent-prod-01",
                    "capabilities": ["scan", "tls", "dns", "osint"],
                    "version": "2.0.0",
                    "tags": {"env": "prod", "region": "us-east-1"},
                }
            ]
        }
    }


class AgentTaskComplete(BaseModel):
    """Sent by the agent when a scan job finishes (success or failure)."""

    error: Optional[str] = Field(
        None,
        description=(
            "Error message if the scan failed. "
            "Omit or set to null on successful completion."
        ),
    )
