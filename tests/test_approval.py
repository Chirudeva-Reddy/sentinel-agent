"""Unit tests for ApprovalCoordinator."""

from __future__ import annotations

import pytest

from sentinel.core.types import (
    ApprovalStatus,
    DecisionAction,
    RiskAssessment,
    RiskTier,
    ToolCallRequest,
)
from sentinel.sandbox.approval import ApprovalCoordinator


@pytest.mark.asyncio
async def test_approval_resolution_flow():
    coordinator = ApprovalCoordinator()
    req = ToolCallRequest(tool_name="delete_account", arguments={"user_id": 123})
    assessment = RiskAssessment(
        overall_score=85.0,
        tier=RiskTier.CRITICAL,
        decision=DecisionAction.REQUIRE_APPROVAL,
        reason="Account deletion risk",
    )

    app_req = coordinator.create_request(req, assessment)
    assert app_req.status == ApprovalStatus.PENDING

    # Resolve approval
    resolved = coordinator.resolve(app_req.id, approve=True, approver="admin-1")
    assert resolved.status == ApprovalStatus.APPROVED
    assert resolved.resolved_by == "admin-1"
    assert resolved.resolved_at is not None


@pytest.mark.asyncio
async def test_approval_timeout():
    coordinator = ApprovalCoordinator(default_timeout=0.1)
    req = ToolCallRequest(tool_name="drop_db", arguments={})
    assessment = RiskAssessment(
        overall_score=95.0,
        tier=RiskTier.CRITICAL,
        decision=DecisionAction.REQUIRE_APPROVAL,
        reason="DB drop risk",
    )

    app_req = coordinator.create_request(req, assessment)
    # Wait for decision with very short timeout
    resolved = await coordinator.wait_for_decision(app_req.id, timeout=0.1)

    assert resolved.status == ApprovalStatus.REJECTED
    assert resolved.resolved_by == "system-timeout"
