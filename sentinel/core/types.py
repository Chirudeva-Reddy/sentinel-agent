"""Pydantic v2 schemas and type definitions for SentinelAgent."""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


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


class ApprovalRequest(BaseModel):
    """Represents a paused tool call waiting for human authorization."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_call: ToolCallRequest
    assessment: RiskAssessment
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: float = Field(default_factory=time.time)
    resolved_at: float | None = None
    resolved_by: str | None = None
    approval_token: str = Field(default_factory=lambda: uuid.uuid4().hex)


class AuditRecord(BaseModel):
    """Cryptographically chained ledger record for tamper-evident auditing."""

    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str
    previous_hash: str
    current_hash: str
    event_type: str
    payload: dict[str, Any]


class PolicyConfig(BaseModel):
    """Configurable security policy for SentinelAgent gateway."""

    safe_threshold: float = 30.0
    critical_threshold: float = 70.0
    allowed_tools: list[str] = Field(default_factory=list)
    blocked_tools: list[str] = Field(default_factory=list)
    require_approval_tools: list[str] = Field(
        default_factory=lambda: [
            "execute_bash",
            "shell",
            "run_command",
            "terminal",
            "delete_file",
            "drop_database",
            "make_payment",
            "send_email",
        ]
    )
    sensitive_paths: list[str] = Field(
        default_factory=lambda: [
            "/etc",
            "~/.ssh",
            "~/.aws",
            ".env",
            "id_rsa",
            "id_ed25519",
            "/var/run/docker.sock",
        ]
    )
    blocked_commands: list[str] = Field(
        default_factory=lambda: [
            "rm -rf /",
            "rm -rf *",
            "mkfs",
            "dd if=",
            ":(){ :|:& };:",
            "chmod -R 777 /",
            "wget http",
            "curl http://",
            "nc -e",
        ]
    )
