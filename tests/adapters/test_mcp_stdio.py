"""End to end over real processes: MCP client -> `sentinel mcp-proxy` (subprocess) -> toy MCP server
(subprocess). The approval is resolved from this process through the shared SQLite store, the way the
dashboard/API would do it."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from sentinel.sandbox.approval import ApprovalCoordinator, ApprovalStore

pytestmark = pytest.mark.integration
TOY = str(Path(__file__).parents[1] / "toy_mcp_server.py")


async def test_proxy_over_stdio_with_cross_process_approval(tmp_path, monkeypatch):
    home, log = tmp_path / "home", tmp_path / "toy.log"
    monkeypatch.setenv("SENTINEL_HOME", str(home))  # the approver shares the proxy's store and keys
    env = {"SENTINEL_HOME": str(home), "TOY_LOG": str(log), "PYTHONPATH": str(Path(TOY).parents[1])}
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "sentinel.cli", "mcp-proxy", "--", sys.executable, TOY], env=env
    )

    async def approve_when_pending():
        while not (home / "approvals.db").exists():
            await asyncio.sleep(0.05)
        coord = ApprovalCoordinator(ApprovalStore(home / "approvals.db"))
        while not coord.list_pending():
            await asyncio.sleep(0.05)
        coord.resolve(coord.list_pending()[0].id, approve=True, approver="remote-human")

    async with Client(params, read_timeout_seconds=30) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {"calculator", "execute_bash", "bypass_security", "fetch_url"} <= names

        blocked = await client.call_tool("bypass_security", {})
        assert blocked.is_error

        approver = asyncio.create_task(approve_when_pending())
        ran = await client.call_tool("execute_bash", {"command": "ls"})
        await approver
        assert "ran: ls" in ran.content[0].text

    assert log.read_text().split() == ["execute_bash"]


def test_upstream_env_excludes_sentinel_secrets(monkeypatch):
    import sentinel.adapters.mcp_proxy as proxy

    monkeypatch.setenv("SENTINEL_APPROVAL_KEY", "secret")
    monkeypatch.setenv("UPSTREAM_TOKEN", "for-the-server")
    seen = {}
    monkeypatch.setattr(proxy.anyio, "run", lambda fn, target: seen.update(target=target))
    proxy.run(["npx", "server"])
    env = seen["target"].env
    assert env["UPSTREAM_TOKEN"] == "for-the-server" and not any(k.startswith("SENTINEL_") for k in env)
