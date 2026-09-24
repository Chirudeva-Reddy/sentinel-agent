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
from sentinel.detectors import Detector, load_detectors
from sentinel.normalize import NormalizedCall, normalize
from sentinel.sandbox.approval import ApprovalCoordinator
from sentinel.sandbox.ledger import AuditLedger


def aggregate(scores: list[float], method: str = "noisy_or") -> float:
    """Combine 0-100 detector scores. noisy_or treats them as independent evidence:
    two medium signals from different detectors corroborate into a high one; max ignores corroboration."""
    if not scores:
        return 0.0
    if method == "max":
        return max(scores)
    miss = 1.0
    for s in scores:
        miss *= 1 - min(max(s, 0.0), 100.0) / 100
    return round((1 - miss) * 100, 4)


_RANK = {
    DecisionAction.ALLOW: 0,
    DecisionAction.WARN_AND_ALLOW: 1,
    DecisionAction.REQUIRE_APPROVAL: 2,
    DecisionAction.BLOCK: 3,
}
_TIER_DECISION = {
    RiskTier.CRITICAL: (
        DecisionAction.REQUIRE_APPROVAL,
        "Critical risk score ({score}/100) exceeded safety threshold. Execution quarantined pending human sign-off.",
    ),
    RiskTier.SUSPICIOUS: (
        DecisionAction.WARN_AND_ALLOW,
        "Suspicious risk score ({score}/100). Tool call allowed with telemetry alert and detailed audit capture.",
    ),
    RiskTier.SAFE: (DecisionAction.ALLOW, "Tool call cleared all security heuristics. Low blast radius."),
}


class SentinelGateway:
    """Interception gateway that audits, scores, and gates all agent tool invocations."""

    def __init__(
        self,
        policy: PolicyEngine | None = None,
        ledger: AuditLedger | None = None,
        approval_coordinator: ApprovalCoordinator | None = None,
        detectors: list[Detector] | None = None,
    ) -> None:
        self.policy = policy or PolicyEngine()
        self.ledger = ledger or AuditLedger()
        self.approval = approval_coordinator or ApprovalCoordinator()
        self.detectors = detectors if detectors is not None else load_detectors(self.policy)

    def _run_detectors(self, call: NormalizedCall) -> list[DetectorFinding]:
        """Runs every detector. A crash or a blown time budget is a SUSPICIOUS finding, never a skip."""
        cfg = self.policy.config
        suspicious = (cfg.safe_threshold + cfg.critical_threshold) / 2
        findings = []
        for det in self.detectors:
            t0 = time.perf_counter()
            try:
                finding = det.analyze(call)
            except Exception as exc:  # noqa: BLE001 - fail closed on any detector bug
                finding = DetectorFinding(
                    detector_name=det.NAME,
                    risk_score=suspicious,
                    severity=RiskTier.SUSPICIOUS,
                    description=f"Detector error (fail closed): {type(exc).__name__}: {exc}",
                    metadata={"error": True},
                )
            elapsed_ms = (time.perf_counter() - t0) * 1000
            if elapsed_ms > cfg.detector_budget_ms and finding.risk_score < suspicious:
                # ponytail: measured after the fact, Python can't pre-empt a running regex. Bounded
                # patterns + the 64 KB input cap are what actually keep detectors fast.
                finding = finding.model_copy(
                    update={
                        "risk_score": suspicious,
                        "severity": RiskTier.SUSPICIOUS,
                        "description": f"Detector exceeded {cfg.detector_budget_ms:.0f} ms budget ({elapsed_ms:.0f} ms)",
                    }
                )
            findings.append(finding)
        return findings

    def inspect(self, tool_call: ToolCallRequest) -> RiskAssessment:
        """Synchronously analyzes a tool call, computes risk scores and records audit logs."""
        start_time = time.perf_counter()

        call = normalize(tool_call)
        findings = self._run_detectors(call)
        cfg = self.policy.config
        overall_score = round(aggregate([f.risk_score for f in findings], cfg.aggregation), 2)
        if overall_score >= cfg.critical_threshold:
            tier = RiskTier.CRITICAL
        elif overall_score >= cfg.safe_threshold:
            tier = RiskTier.SUSPICIOUS
        else:
            tier = RiskTier.SAFE

        decision, reason = _TIER_DECISION[tier]
        reason = reason.format(score=overall_score)
        # Policy floors: detectors can only make a decision stricter than the policy, never looser.
        if self.policy.is_tool_blocked(call.tool):
            decision, reason = DecisionAction.BLOCK, f"Tool '{call.tool}' is explicitly blocked by security policy."
        elif (
            self.policy.does_tool_require_approval(call.tool)
            and _RANK[decision] < _RANK[DecisionAction.REQUIRE_APPROVAL]
        ):
            decision, reason = DecisionAction.REQUIRE_APPROVAL, f"Policy requires human approval for '{call.tool}'."
        elif not self.policy.is_tool_known(call.tool) and _RANK[decision] < _RANK[cfg.unknown_tool_action]:
            decision, reason = cfg.unknown_tool_action, f"Tool '{call.tool}' is not in the policy (deny by default)."

        requires_approval = decision == DecisionAction.REQUIRE_APPROVAL
        approval_id = None
        if requires_approval:
            approval_id = self.approval.create_request(
                tool_call=tool_call,
                assessment=RiskAssessment(
                    overall_score=overall_score,
                    tier=tier,
                    decision=decision,
                    findings=findings,
                    requires_human_approval=True,
                    reason=reason,
                ),
            ).id

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

        if assessment.decision == DecisionAction.REQUIRE_APPROVAL and assessment.approval_id:
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
