"""Unified Zero-Trust Security Gateway for AI Agent Tool Execution."""

from __future__ import annotations

import time
from typing import Any

from sentinel.core.policy import PolicyEngine
from sentinel.core.types import (
    ApprovalStatus,
    DecisionAction,
    DetectorFinding,
    RiskAssessment,
    RiskTier,
    ToolCallRequest,
)
from sentinel.detectors.argument_validator import ArgumentValidator
from sentinel.detectors.blast_radius import BlastRadiusDetector
from sentinel.detectors.injection import InjectionDetector
from sentinel.sandbox.approval import ApprovalCoordinator
from sentinel.sandbox.ledger import AuditLedger


class SentinelGateway:
    """Interception gateway that audits, scores, and gates all agent tool invocations."""

    def __init__(
        self,
        policy: PolicyEngine | None = None,
        ledger: AuditLedger | None = None,
        approval_coordinator: ApprovalCoordinator | None = None,
        auto_escalate_approval: bool = True,
    ):
        self.policy = policy or PolicyEngine()
        self.ledger = ledger or AuditLedger()
        self.approval = approval_coordinator or ApprovalCoordinator()
        self.auto_escalate_approval = auto_escalate_approval

        # Initialize detector suite
        self.injection_detector = InjectionDetector()
        self.blast_radius_detector = BlastRadiusDetector(self.policy)
        self.argument_validator = ArgumentValidator()

    def inspect(self, tool_call: ToolCallRequest) -> RiskAssessment:
        """Synchronously analyzes a tool call, computes risk scores and records audit logs."""
        start_time = time.perf_counter()

        findings: list[DetectorFinding] = []

        # 1. Run Detectors
        injection_res = self.injection_detector.analyze(tool_call)
        blast_res = self.blast_radius_detector.analyze(tool_call)
        arg_res = self.argument_validator.analyze(tool_call)

        findings.extend([injection_res, blast_res, arg_res])

        # 2. Compute Aggregate Score (conservative maximum of specialized detectors)
        max_score = max(f.risk_score for f in findings)
        overall_score = round(max_score, 2)

        # 3. Determine Risk Tier
        if overall_score >= self.policy.config.critical_threshold:
            tier = RiskTier.CRITICAL
        elif overall_score >= self.policy.config.safe_threshold:
            tier = RiskTier.SUSPICIOUS
        else:
            tier = RiskTier.SAFE

        # 4. Determine Enforcement Decision
        # If tool is explicitly blocked or score is 100 on catastrophic command
        if self.policy.is_tool_blocked(tool_call.tool_name):
            decision = DecisionAction.BLOCK
            reason = f"Tool '{tool_call.tool_name}' is explicitly blocked by security policy."
            requires_approval = False
            approval_id = None
        elif tier == RiskTier.CRITICAL:
            decision = DecisionAction.REQUIRE_APPROVAL
            reason = (
                f"Critical risk score ({overall_score}/100) exceeded safety threshold. "
                "Execution quarantined pending human sign-off."
            )
            requires_approval = True
            approval_req = self.approval.create_request(
                tool_call=tool_call,
                assessment=RiskAssessment(
                    overall_score=overall_score,
                    tier=tier,
                    decision=decision,
                    findings=findings,
                    latency_ms=0.0,
                    requires_human_approval=True,
                    reason=reason,
                ),
            )
            approval_id = approval_req.id
        elif tier == RiskTier.SUSPICIOUS:
            decision = DecisionAction.WARN_AND_ALLOW
            reason = (
                f"Suspicious risk score ({overall_score}/100). "
                "Tool call allowed with telemetry alert and detailed audit capture."
            )
            requires_approval = False
            approval_id = None
        else:
            decision = DecisionAction.ALLOW
            reason = "Tool call cleared all security heuristics. Low blast radius."
            requires_approval = False
            approval_id = None

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        assessment = RiskAssessment(
            overall_score=overall_score,
            tier=tier,
            decision=decision,
            findings=findings,
            latency_ms=latency_ms,
            requires_human_approval=requires_approval,
            approval_id=approval_id,
            reason=reason,
        )

        # 5. Cryptographic Audit Append
        self.ledger.append(
            event_type=f"TOOL_{decision.value}",
            payload={
                "tool_call_id": tool_call.id,
                "tool_name": tool_call.tool_name,
                "arguments": tool_call.arguments,
                "overall_score": overall_score,
                "tier": tier.value,
                "decision": decision.value,
                "latency_ms": latency_ms,
                "approval_id": approval_id,
            },
        )

        return assessment

    async def execute_gated(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        executor_func: Any,
        raw_prompt_context: str | None = None,
        agent_id: str = "agent-alpha",
    ) -> dict[str, Any]:
        """Convenience method: intercepts, requests approval if critical, and executes only if approved."""
        request = ToolCallRequest(
            tool_name=tool_name,
            arguments=arguments,
            raw_prompt_context=raw_prompt_context,
            agent_id=agent_id,
        )

        assessment = self.inspect(request)

        if assessment.decision == DecisionAction.BLOCK:
            return {
                "success": False,
                "blocked": True,
                "reason": assessment.reason,
                "assessment": assessment.model_dump(),
            }

        if assessment.decision == DecisionAction.REQUIRE_APPROVAL:
            # Wait for human approval
            req = await self.approval.wait_for_decision(assessment.approval_id)
            if req.status != ApprovalStatus.APPROVED:
                self.ledger.append(
                    event_type="APPROVAL_REJECTED",
                    payload={"approval_id": req.id, "tool_name": tool_name},
                )
                return {
                    "success": False,
                    "blocked": True,
                    "rejected_by_human": True,
                    "reason": "Human operator rejected the execution request or approval timed out.",
                    "assessment": assessment.model_dump(),
                }
            self.ledger.append(
                event_type="APPROVAL_GRANTED",
                payload={"approval_id": req.id, "tool_name": tool_name, "approver": req.resolved_by},
            )

        # If allowed or approved, execute the real function
        try:
            if callable(executor_func):
                result = executor_func(**arguments)
            else:
                result = executor_func
            return {
                "success": True,
                "blocked": False,
                "result": result,
                "assessment": assessment.model_dump(),
            }
        except Exception as exc:
            return {
                "success": False,
                "blocked": False,
                "error": str(exc),
                "assessment": assessment.model_dump(),
            }
