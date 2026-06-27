from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Mission:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent_type: str = ""
    target: str = ""
    service: Optional[str] = None
    port: Optional[int] = None
    context: dict = field(default_factory=dict)
    cves: list = field(default_factory=list)
    instructions: dict = field(default_factory=dict)
    ttl: int = 300


@dataclass
class AgentReport:
    mission_id: str = ""
    agent_type: str = ""
    target: str = ""
    success: bool = False
    artifacts: dict = field(default_factory=dict)
    signals: list = field(default_factory=list)
    logs: list = field(default_factory=list)
    error: Optional[str] = None
    poc: Optional[dict] = None
    chain_result: Optional[dict] = None
