"""Split-brain (issue 7): two gateways on one store see and release each other's approvals."""

from __future__ import annotations

import asyncio

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import ApprovalStatus, ToolCallRequest
from sentinel.sandbox.approval import ApprovalCoordinator, ApprovalStore


async def test_resolve_on_one_instance_releases_waiter_on_other(tmp_path):
    db = tmp_path / "approvals.db"
    api = SentinelGateway(approval_coordinator=ApprovalCoordinator(ApprovalStore(db), poll_interval=0.02))
    dashboard = ApprovalCoordinator(ApprovalStore(db))

    aid = api.inspect(ToolCallRequest(tool_name="execute_bash", arguments={"command": "ls"})).approval_id
    assert [r.id for r in dashboard.list_pending()] == [aid]

    waiter = asyncio.create_task(api.approval.wait_for_decision(aid, timeout=5))
    await asyncio.sleep(0.05)
    dashboard.resolve(aid, approve=True, approver="dash")
    req = await asyncio.wait_for(waiter, 2)
    assert req.status == ApprovalStatus.APPROVED and req.resolved_by == "dash"


def test_double_resolve_keeps_first_decision(tmp_path):
    a = ApprovalCoordinator(ApprovalStore(tmp_path / "db"))
    b = ApprovalCoordinator(ApprovalStore(tmp_path / "db"))
    aid = SentinelGateway(approval_coordinator=a).inspect(ToolCallRequest(tool_name="shell", arguments={})).approval_id
    a.resolve(aid, approve=False, approver="first")
    assert b.resolve(aid, approve=True, approver="second").status == ApprovalStatus.REJECTED
