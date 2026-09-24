"""Sentinel MCP proxy: sits between an MCP client (Claude Desktop, an IDE, an agent) and an upstream MCP
server. tools/list is forwarded; every tools/call goes through SentinelGateway.execute_gated, so it is
inspected, paused for human approval when required, and its output is guarded before the model sees it.

    sentinel mcp-proxy -- npx -y @modelcontextprotocol/server-filesystem ~/projects

Approvals are resolved through the shared store (API/dashboard with SENTINEL_HOME pointing at the
same directory). Requires the [mcp] extra.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import anyio
import mcp_types as types
from mcp import Client, StdioServerParameters
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from sentinel.core.gateway import SentinelGateway


def _text(result: types.CallToolResult) -> str:
    return "\n".join(c.text for c in result.content if isinstance(c, types.TextContent))


def _error(message: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=message)], is_error=True)


def build_proxy(upstream: Client, gateway: SentinelGateway, session_id: str | None = None) -> Server[Any]:
    """An MCP Server that forwards to a connected upstream Client through the gateway."""
    session = session_id or f"mcp-{uuid.uuid4().hex[:12]}"

    sources = {t.strip().lower() for t in gateway.policy.config.taint_sources}

    async def list_tools(ctx: Any, params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
        listed = await upstream.list_tools(cursor=params.cursor if params else None)
        # Untrusted-source tools return guarded text only (see call_tool), so they can't promise a schema.
        tools = [t.model_copy(update={"output_schema": None}) if t.name.lower() in sources else t for t in listed.tools]
        return listed.model_copy(update={"tools": tools})

    async def call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        upstream_result: list[types.CallToolResult] = []

        async def run(**arguments: Any) -> str:
            res = await upstream.call_tool(params.name, arguments)
            upstream_result.append(res)
            return _text(res)

        out = await gateway.execute_gated(
            params.name, dict(params.arguments or {}), run, agent_id="mcp-client", session_id=session
        )
        if out.get("blocked"):
            return _error(f"Sentinel blocked this call: {out['reason']}")
        if not out["success"]:
            return _error(f"Tool error: {out.get('error')}")

        res = upstream_result[0]
        guard = out["result_guard"]
        other = [c for c in res.content if not isinstance(c, types.TextContent)]
        text = types.TextContent(type="text", text=out["sanitized_result"])
        # Structured content would bypass the guard, so it is dropped for untrusted sources.
        structured = None if guard["untrusted"] else res.structured_content
        return types.CallToolResult(content=[text, *other], structured_content=structured, is_error=res.is_error)

    return Server("sentinel-mcp-proxy", version="0.2.0", on_list_tools=list_tools, on_call_tool=call_tool)


async def serve(upstream: StdioServerParameters | str, gateway: SentinelGateway | None = None) -> None:
    """Run the proxy on this process's stdio against an upstream (stdio command or streamable-HTTP URL)."""
    gw = gateway or SentinelGateway()
    async with Client(upstream) as up:
        server = build_proxy(up, gw)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())


def run(command: list[str]) -> None:
    if not command:
        raise SystemExit("usage: sentinel mcp-proxy -- <upstream command...> | <http(s) url>")
    target: StdioServerParameters | str
    if len(command) == 1 and command[0].startswith(("http://", "https://")):
        target = command[0]
    else:
        # Upstream servers often need their own env (API keys); Sentinel's keys never go to them.
        env = {k: v for k, v in os.environ.items() if not k.startswith("SENTINEL_")}
        target = StdioServerParameters(command=command[0], args=command[1:], env=env)
    anyio.run(serve, target)
