"""Every adapter must honour the same contract:
blocked calls never reach the tool, approvals pause and resume, rejections don't run,
and tool output goes through the output guard before the model sees it.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import pytest
from mcp import Client

from sentinel.adapters.mcp_proxy import build_proxy
from sentinel.adapters.openai_adapter import SentinelOpenAIWrapper
from sentinel.core.gateway import SentinelGateway
from sentinel.sandbox.approval import ApprovalCoordinator, ApprovalStore
from tests import toy_mcp_server as toy

Invoke = Callable[[str, dict[str, Any]], Awaitable[str]]


def _gateway() -> SentinelGateway:
    coord = ApprovalCoordinator(ApprovalStore(":memory:"), default_timeout=2, poll_interval=0.01)
    return SentinelGateway(approval_coordinator=coord)


@asynccontextmanager
async def mcp_adapter(gw: SentinelGateway):
    async with Client(toy.server) as upstream, Client(build_proxy(upstream, gw)) as client:

        async def invoke(tool: str, args: dict[str, Any]) -> str:
            res = await client.call_tool(tool, args)
            return "\n".join(c.text for c in res.content if hasattr(c, "text"))

        yield invoke


@asynccontextmanager
async def openai_adapter(gw: SentinelGateway):
    wrapper = SentinelOpenAIWrapper(gw)
    for name in ("calculator", "execute_bash", "bypass_security", "fetch_url"):
        wrapper.register_tool(name, getattr(toy, name))

    async def invoke(tool: str, args: dict[str, Any]) -> str:
        return (await wrapper.call(tool, json.dumps(args)))["content"]

    yield invoke


ADAPTERS = pytest.mark.parametrize("adapter", [mcp_adapter, openai_adapter], ids=["mcp", "openai"])


@pytest.fixture(autouse=True)
def _reset_calls():
    toy.CALLS.clear()


async def _decide_first_pending(gw: SentinelGateway, approve: bool) -> None:
    while not gw.approval.list_pending():
        await asyncio.sleep(0.01)
    gw.approval.resolve(gw.approval.list_pending()[0].id, approve=approve, approver="test")


@ADAPTERS
async def test_allowed_call_runs(adapter):
    gw = _gateway()
    async with adapter(gw) as invoke:
        assert "= 1+1" in await invoke("calculator", {"expression": "1+1"})
    assert toy.CALLS == ["calculator"]


@ADAPTERS
async def test_blocked_call_never_reaches_tool(adapter):
    gw = _gateway()
    async with adapter(gw) as invoke:
        out = await invoke("bypass_security", {})
    assert "blocked" in out.lower()
    assert toy.CALLS == []


@ADAPTERS
async def test_approval_pauses_then_resumes(adapter):
    gw = _gateway()
    async with adapter(gw) as invoke:
        decider = asyncio.create_task(_decide_first_pending(gw, approve=True))
        out = await invoke("execute_bash", {"command": "ls"})
        await decider
    assert "ran: ls" in out
    assert toy.CALLS == ["execute_bash"]


@ADAPTERS
async def test_rejected_call_does_not_run(adapter):
    gw = _gateway()
    async with adapter(gw) as invoke:
        decider = asyncio.create_task(_decide_first_pending(gw, approve=False))
        out = await invoke("execute_bash", {"command": "rm -rf ./build"})
        await decider
    assert "rejected" in out.lower()
    assert toy.CALLS == []


@ADAPTERS
async def test_output_goes_through_guard(adapter):
    gw = _gateway()
    async with adapter(gw) as invoke:
        out = await invoke("fetch_url", {"url": "https://example.com/notes"})
    assert "Release notes v2.1" in out
    assert "<<untrusted-data" in out and 'injection-suspected="true"' in out
