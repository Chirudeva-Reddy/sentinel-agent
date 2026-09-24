"""Tool-call wrapper for OpenAI-style function calling (also works for any framework that hands you
a tool name + JSON arguments). Calls go through SentinelGateway.execute_gated: inspection, human
approval when required (it waits instead of hard-blocking), and output guarding.

    wrapper = SentinelOpenAIWrapper()
    wrapper.register_tool("read_file", read_file)
    out = await wrapper.call(tool_call.function.name, tool_call.function.arguments)
    messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": out["content"]})
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

from sentinel.core.gateway import SentinelGateway


class SentinelOpenAIWrapper:
    def __init__(self, gateway: SentinelGateway | None = None, session_id: str = "session-001") -> None:
        self.gateway = gateway or SentinelGateway()
        self.session_id = session_id
        self.tool_registry: dict[str, Callable[..., Any]] = {}

    def register_tool(self, name: str, func: Callable[..., Any]) -> None:
        self.tool_registry[name] = func

    async def call(
        self, tool_name: str, arguments: str | dict[str, Any], prompt_context: str | None = None
    ) -> dict[str, Any]:
        """Returns execute_gated's dict plus `content`: the string to send back as the tool message."""
        if isinstance(arguments, str):
            try:
                args = json.loads(arguments or "{}")
            except ValueError:
                args = {"raw_arguments": arguments}
        else:
            args = dict(arguments)
        if not isinstance(args, dict):
            args = {"value": args}

        func = self.tool_registry.get(tool_name)
        if func is None:
            return {"success": False, "blocked": False, "content": f"Error: tool '{tool_name}' is not registered."}

        out = await self.gateway.execute_gated(
            tool_name, args, func, raw_prompt_context=prompt_context, session_id=self.session_id
        )
        if out.get("blocked"):
            out["content"] = f"Sentinel blocked this call: {out['reason']}"
        elif not out["success"]:
            out["content"] = f"Error: {out.get('error')}"
        else:
            out["content"] = out["sanitized_result"]
        return out

    def intercept_and_call(
        self, tool_name: str, arguments: str | dict[str, Any], prompt_context: str | None = None
    ) -> dict[str, Any]:
        """Synchronous convenience for scripts (not callable from inside a running event loop)."""
        return asyncio.run(self.call(tool_name, arguments, prompt_context))
