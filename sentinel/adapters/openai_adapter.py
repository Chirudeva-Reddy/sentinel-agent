"""OpenAI Function Calling & Agent Tool Interceptor Adapter."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import ToolCallRequest


class SentinelOpenAIWrapper:
    """Interception wrapper for agents using OpenAI or LangChain tool-calling APIs."""

    def __init__(self, gateway: SentinelGateway | None = None):
        self.gateway = gateway or SentinelGateway()
        self.tool_registry: dict[str, Callable[..., Any]] = {}

    def register_tool(self, name: str, func: Callable[..., Any]) -> None:
        self.tool_registry[name] = func

    def intercept_and_call(
        self,
        tool_name: str,
        arguments_json_or_dict: Any,
        prompt_context: str | None = None,
    ) -> dict[str, Any]:
        """Intercepts an OpenAI tool_call object, audits it, and calls registered function if safe."""
        if isinstance(arguments_json_or_dict, str):
            try:
                args = json.loads(arguments_json_or_dict)
            except Exception:
                args = {"raw_arguments": arguments_json_or_dict}
        elif isinstance(arguments_json_or_dict, dict):
            args = arguments_json_or_dict
        else:
            args = {"value": str(arguments_json_or_dict)}

        req = ToolCallRequest(
            tool_name=tool_name,
            arguments=args,
            raw_prompt_context=prompt_context,
        )

        assessment = self.gateway.inspect(req)

        if assessment.decision.value in ("BLOCK", "REQUIRE_APPROVAL"):
            return {
                "executed": False,
                "blocked": True,
                "reason": assessment.reason,
                "risk_score": assessment.overall_score,
                "tier": assessment.tier.value,
                "assessment": assessment.model_dump(),
            }

        target_func = self.tool_registry.get(tool_name)
        if not target_func:
            return {
                "executed": False,
                "error": f"Tool '{tool_name}' not registered in Sentinel executor.",
                "assessment": assessment.model_dump(),
            }

        try:
            result = target_func(**args)
            return {
                "executed": True,
                "blocked": False,
                "result": result,
                "risk_score": assessment.overall_score,
                "tier": assessment.tier.value,
                "assessment": assessment.model_dump(),
            }
        except Exception as err:
            return {
                "executed": False,
                "error": str(err),
                "assessment": assessment.model_dump(),
            }
