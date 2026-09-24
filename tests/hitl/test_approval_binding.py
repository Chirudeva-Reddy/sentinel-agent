"""An approval authorises one exact call, once, before it expires (issues 2 and 10)."""

from __future__ import annotations

import asyncio

import pytest

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import ApprovalStatus, ToolCallRequest
from sentinel.sandbox.approval import ApprovalCoordinator, ApprovalError, ApprovalStore, DigestMismatch, call_digest

RM = ToolCallRequest(tool_name="execute_bash", arguments={"command": "rm -rf ./build"})


def _approved(coord: ApprovalCoordinator, call: ToolCallRequest = RM):
    gw = SentinelGateway(approval_coordinator=coord)
    aid = gw.inspect(call).approval_id
    return coord.resolve(aid, approve=True, approver="alice")


def test_digest_is_canonical():
    a = ToolCallRequest(tool_name="Execute_Bash", arguments={"b": 1, "a": [1, {"y": 2, "x": 3}]})
    b = ToolCallRequest(tool_name="execute_bash", arguments={"a": [1, {"x": 3, "y": 2}], "b": 1})
    assert call_digest(a) == call_digest(b)
    assert call_digest(a) != call_digest(b.model_copy(update={"arguments": {"b": 2}}))


def test_token_redeems_only_the_approved_call():
    coord = ApprovalCoordinator(ApprovalStore(":memory:"))
    req = _approved(coord)
    other = ToolCallRequest(tool_name="execute_bash", arguments={"command": "rm -rf /"})
    with pytest.raises(DigestMismatch):
        coord.redeem(req.id, req.approval_token, other)
    coord.redeem(req.id, req.approval_token, RM)


def test_token_is_single_use():
    coord = ApprovalCoordinator(ApprovalStore(":memory:"))
    req = _approved(coord)
    coord.redeem(req.id, req.approval_token, RM)
    with pytest.raises(ApprovalError, match="already used"):
        coord.redeem(req.id, req.approval_token, RM)


def test_forged_token_rejected():
    coord = ApprovalCoordinator(ApprovalStore(":memory:"))
    req = _approved(coord)
    with pytest.raises(ApprovalError, match="invalid token"):
        coord.redeem(req.id, "0" * 64, RM)


def test_pending_or_rejected_cannot_be_redeemed():
    coord = ApprovalCoordinator(ApprovalStore(":memory:"))
    gw = SentinelGateway(approval_coordinator=coord)
    aid = gw.inspect(RM).approval_id
    with pytest.raises(ApprovalError):
        coord.redeem(aid, "", RM)
    rejected = coord.resolve(aid, approve=False, approver="bob")
    assert rejected.approval_token is None


def test_expired_token_rejected():
    coord = ApprovalCoordinator(ApprovalStore(":memory:"), token_ttl=-1)
    req = _approved(coord)
    with pytest.raises(ApprovalError, match="expired"):
        coord.redeem(req.id, req.approval_token, RM)


async def test_timeout_is_expired_not_rejected():
    coord = ApprovalCoordinator(ApprovalStore(":memory:"), default_timeout=0.05)
    aid = SentinelGateway(approval_coordinator=coord).inspect(RM).approval_id
    req = await coord.wait_for_decision(aid)
    assert req.status == ApprovalStatus.EXPIRED


async def test_arguments_mutated_during_wait_raise_digest_mismatch():
    coord = ApprovalCoordinator(ApprovalStore(":memory:"))
    gw = SentinelGateway(approval_coordinator=coord)
    args = {"command": "rm -rf ./build"}
    ran = []

    async def approve_after_swap():
        while not coord.list_pending():
            await asyncio.sleep(0.01)
        args["command"] = "rm -rf /"  # attacker swaps the argument after the human looked
        coord.resolve(coord.list_pending()[0].id, approve=True, approver="alice")

    task = asyncio.create_task(approve_after_swap())
    with pytest.raises(DigestMismatch):
        await gw.execute_gated("execute_bash", args, lambda command: ran.append(command))
    await task
    assert ran == []


async def test_notifier_called_for_pending():
    seen = []
    coord = ApprovalCoordinator(ApprovalStore(":memory:"), notifier=seen.append)
    SentinelGateway(approval_coordinator=coord).inspect(RM)
    assert len(seen) == 1 and seen[0].tool_call.tool_name == "execute_bash"
