"""Core primitives and gateway for SentinelAgent."""

from __future__ import annotations

from typing import Any

from sentinel.core.types import (
    ApprovalRequest,
    ApprovalStatus,
    AuditRecord,
    DecisionAction,
    DetectorFinding,
    PolicyConfig,
    RiskAssessment,
    RiskTier,
    ToolCallRequest,
)


def __getattr__(name: str) -> Any:
    # Lazy: importing sentinel.core.types must not pull in the gateway (and with it every detector/store).
    if name == "SentinelGateway":
        from sentinel.core.gateway import SentinelGateway

        return SentinelGateway
    if name == "PolicyEngine":
        from sentinel.core.policy import PolicyEngine

        return PolicyEngine
    raise AttributeError(name)


__all__ = [
    "ApprovalRequest",
    "ApprovalStatus",
    "AuditRecord",
    "DecisionAction",
    "DetectorFinding",
    "PolicyConfig",
    "PolicyEngine",
    "RiskAssessment",
    "RiskTier",
    "SentinelGateway",
    "ToolCallRequest",
]
