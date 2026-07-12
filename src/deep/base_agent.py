from __future__ import annotations

import logging
from typing import Optional

from src.deep.models import Mission, AgentReport

log = logging.getLogger("netlogic.deep.agent")


class BaseAgent:
    def __init__(self, mission: Mission) -> None:
        self.mission = mission
        self._timed_out = False

    def execute(self) -> AgentReport:
        raise NotImplementedError

    def _make_report(
        self,
        success: bool = True,
        artifacts: Optional[dict] = None,
        signals: Optional[list] = None,
        logs: Optional[list] = None,
        error: Optional[str] = None,
    ) -> AgentReport:
        return AgentReport(
            mission_id=self.mission.id,
            agent_type=self.mission.agent_type,
            target=self.mission.target,
            success=success,
            artifacts=artifacts or {},
            signals=signals or [],
            logs=logs or [],
            error=error,
        )
