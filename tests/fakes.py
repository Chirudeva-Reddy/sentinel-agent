"""Test doubles. ScriptedAgent replays tool calls + canned tool results through the gateway, no LLM."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import DecisionAction


@dataclass
class Step:
    tool: str
    args: dict[str, Any]
    result: Any = "ok"


@dataclass
class ScriptedAgent:
    gateway: SentinelGateway
    session_id: str = "s1"
    decisions: list[DecisionAction] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)

    async def run(self, steps: list[Step]) -> list[DecisionAction]:
        # Every approval is rejected, so "REQUIRE_APPROVAL" means the step did not run.
        self.gateway.approval.register_cli_handler(lambda req: False)
        for step in steps:

            def tool(_step: Step = step, **_: Any) -> Any:
                self.executed.append(_step.tool)
                return _step.result

            out = await self.gateway.execute_gated(step.tool, step.args, tool, session_id=self.session_id)
            self.decisions.append(DecisionAction(out["assessment"]["decision"]))
        return self.decisions
