"""Pydantic v2 schemas and type definitions for SentinelAgent."""

from __future__ import annotations

import time
import uuid
from enum import Enum
from importlib.resources import files
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class RiskTier(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class DecisionAction(str, Enum):
    ALLOW = "ALLOW"
    WARN_AND_ALLOW = "WARN_AND_ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ToolCallRequest(BaseModel):
    """Represents an intercepted tool call candidate emitted by an AI agent."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent_id: str = "agent-alpha"
    session_id: str = "session-001"
    timestamp: float = Field(default_factory=time.time)
    raw_prompt_context: str | None = None


class DetectorFinding(BaseModel):
    """Result of an individual detector inspecting the tool call."""

    detector_name: str
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Risk score 0-100")
    severity: RiskTier
    description: str
    matched_patterns: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskAssessment(BaseModel):
    """Aggregate evaluation and decision for a tool call."""

    overall_score: float = Field(..., ge=0.0, le=100.0)
    tier: RiskTier
    decision: DecisionAction
    findings: list[DetectorFinding] = Field(default_factory=list)
    latency_ms: float = 0.0
    requires_human_approval: bool = False
    approval_id: str | None = None
    reason: str


class ResultAssessment(BaseModel):
    """Verdict on a tool's OUTPUT before it goes back to the model."""

    tool_name: str
    untrusted: bool
    """Output came from a policy taint source (web, email, files): treat as data, never as instructions."""
    injection_detected: bool
    findings: list[DetectorFinding] = Field(default_factory=list)
    sanitized_text: str
    """What to hand the model: untrusted output is wrapped in explicit data delimiters."""


class ApprovalRequest(BaseModel):
    """Represents a paused tool call waiting for human authorization."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_call: ToolCallRequest
    assessment: RiskAssessment
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: float = Field(default_factory=time.time)
    resolved_at: float | None = None
    resolved_by: str | None = None
    call_digest: str = ""
    """sha256 of the canonical (tool, arguments) the human is approving."""
    approval_token: str | None = None
    """HMAC(id|digest|expiry|approver), issued only on APPROVED; redeemable once, for this digest only."""
    token_expires_at: float | None = None


class AuditRecord(BaseModel):
    """Cryptographically chained ledger record for tamper-evident auditing."""

    model_config = ConfigDict(extra="forbid")

    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    seq: int = 0
    timestamp: str
    previous_hash: str
    current_hash: str
    event_type: str
    payload: dict[str, Any]


def _default_policy() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(files("sentinel.policies").joinpath("default.yaml").read_text("utf-8"))
    return data


class PolicyConfig(BaseModel):
    """Security policy. Defaults come from sentinel/policies/default.yaml (the single source of truth);
    keys missing from a custom policy fall back to it, unknown keys are rejected."""

    model_config = ConfigDict(extra="forbid")

    version: str
    safe_threshold: float = Field(ge=0, le=100)
    critical_threshold: float = Field(ge=0, le=100)
    aggregation: Literal["noisy_or", "max"]
    detector_budget_ms: float = Field(gt=0)
    unknown_tool_action: DecisionAction
    """Decision floor for tools not listed in allowed/require_approval/blocked. Never ALLOW (deny by default)."""
    allowed_hosts: list[str]
    """Hostnames/IPs exempt from SSRF checks, e.g. ["localhost"] for a dev policy."""
    allowed_tools: list[str]
    blocked_tools: list[str]
    require_approval_tools: list[str]
    sensitive_paths: list[str]
    blocked_commands: list[str]
    taint_sources: list[str]
    taint_sinks: dict[str, Literal["high", "low"]]
    taint_min_match: int = Field(ge=8)

    @model_validator(mode="before")
    @classmethod
    def _inherit_defaults(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return {**_default_policy(), **data}
        return data

    @model_validator(mode="after")
    def _check(self) -> PolicyConfig:
        if self.safe_threshold >= self.critical_threshold:
            raise ValueError("safe_threshold must be below critical_threshold")
        if self.unknown_tool_action not in (DecisionAction.REQUIRE_APPROVAL, DecisionAction.BLOCK):
            raise ValueError("unknown_tool_action must be REQUIRE_APPROVAL or BLOCK (deny by default)")
        return self
