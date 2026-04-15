"""
NetLogic API — Agent Pydantic models.

Used by both the agent process (AgentRegistration, AgentTaskComplete)
and the controller routes (AgentRegistration, AgentTaskComplete).
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class AgentRegistration(BaseModel):
    """Payload sent by an agent on first startup to register with the controller."""

    hostname: str = Field(
        ...,
        description="Hostname or human-readable name of the machine running the agent.",
    )
    capabilities: list[str] = Field(
        default_factory=list,
        description=(
            "Scan modules this agent supports, e.g. "
            "['scan', 'tls', 'dns', 'osint', 'probe', 'takeover']."
        ),
    )
    version: str = Field(
        "1.0.0",
        description="Agent software version string.",
    )
    tags: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Arbitrary key/value metadata for filtering/grouping agents, "
            "e.g. {'env': 'prod', 'region': 'us-east-1', 'customer': 'acme'}."
        ),
    )

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
