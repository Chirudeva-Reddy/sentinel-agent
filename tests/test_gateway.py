"""Unit tests for SentinelGateway core."""

from __future__ import annotations

import pytest

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import DecisionAction, RiskTier, ToolCallRequest
from sentinel.sandbox.approval import ApprovalCoordinator
from sentinel.sandbox.ledger import AuditLedger


@pytest.fixture
def gateway(tmp_path):
    log_file = tmp_path / "test_audit.jsonl"
    ledger = AuditLedger(log_file)
    approval = ApprovalCoordinator()
    return SentinelGateway(ledger=ledger, approval_coordinator=approval)


def test_inspect_safe_tool_call(gateway):
    req = ToolCallRequest(
        tool_name="calculator",
        arguments={"expression": "100 + 42"},
    )
    assessment = gateway.inspect(req)

    assert assessment.overall_score < 30.0
    assert assessment.tier == RiskTier.SAFE
    assert assessment.decision == DecisionAction.ALLOW
    assert not assessment.requires_human_approval
    assert assessment.latency_ms >= 0.0


def test_inspect_blocked_tool(gateway):
    req = ToolCallRequest(
        tool_name="bypass_security",
        arguments={},
    )
    assessment = gateway.inspect(req)

    assert assessment.decision == DecisionAction.BLOCK
    assert "explicitly blocked" in assessment.reason


def test_inspect_critical_tool_call(gateway):
    req = ToolCallRequest(
        tool_name="execute_bash",
        arguments={"command": "rm -rf / --no-preserve-root"},
    )
    assessment = gateway.inspect(req)

    assert assessment.overall_score >= 70.0
    assert assessment.tier == RiskTier.CRITICAL
    assert assessment.decision == DecisionAction.REQUIRE_APPROVAL
    assert assessment.requires_human_approval
    assert assessment.approval_id is not None


@pytest.mark.asyncio
async def test_execute_gated_approval_granted(gateway):
    def dummy_tool(command: str):
        return f"Executed: {command}"

    # Register handler to simulate human approving the request
    gateway.approval.register_cli_handler(lambda req: True)

    res = await gateway.execute_gated(
        tool_name="execute_bash",
        arguments={"command": "ls -la"},
        executor_func=dummy_tool,
    )

    assert res["success"] is True
    assert res["blocked"] is False
    assert "Executed: ls -la" in res["result"]


@pytest.mark.asyncio
async def test_execute_gated_approval_rejected(gateway):
    def dummy_tool(command: str):
        return f"Executed: {command}"

    # Register handler to simulate human rejecting the request
    gateway.approval.register_cli_handler(lambda req: False)

    res = await gateway.execute_gated(
        tool_name="execute_bash",
        arguments={"command": "cat /etc/shadow"},
        executor_func=dummy_tool,
    )

    assert res["success"] is False
    assert res["blocked"] is True
    assert res["rejected_by_human"] is True
