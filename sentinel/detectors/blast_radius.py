"""Blast Radius Estimator for AI Agent Tool Invocations."""

from __future__ import annotations

import re
from typing import Any

from sentinel.core.policy import PolicyEngine
from sentinel.core.types import DetectorFinding, RiskTier, ToolCallRequest


class BlastRadiusDetector:
    """Computes the potential operational damage (blast radius) of executing a tool call."""

    NAME = "blast_radius_detector"

    # Category base risks
    EXECUTION_TOOLS = {"execute_bash", "shell", "run_command", "terminal", "eval", "exec", "python_exec"}
    DESTRUCTIVE_FILE_TOOLS = {"delete_file", "remove_directory", "truncate_file", "unlink"}
    DATABASE_TOOLS = {"execute_sql", "query_database", "run_db_migration"}
    PRIVILEGE_TOOLS = {"transfer_funds", "make_payment", "grant_role", "revoke_access", "change_password"}
    READ_ONLY_TOOLS = {"read_file", "view_file", "search_web", "list_directory", "calculator", "get_weather"}

    SQL_DESTRUCTIVE_PATTERNS = [
        r"(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA|VIEW)\b",
        r"(?i)\bTRUNCATE\s+TABLE\b",
        r"(?i)\bDELETE\s+FROM\s+\w+\s*(;|$)",  # DELETE without WHERE clause
        r"(?i)\bALTER\s+TABLE\s+.*?\bDROP\b",
        r"(?i)\bGRANT\s+ALL\b",
    ]

    def __init__(self, policy: PolicyEngine):
        self.policy = policy
        self.compiled_sql = [re.compile(p) for p in self.SQL_DESTRUCTIVE_PATTERNS]

    def _assess_tool_category(self, tool_name: str) -> float:
        tool_clean = tool_name.lower().strip()
        if tool_clean in self.READ_ONLY_TOOLS:
            return 5.0
        if tool_clean in self.PRIVILEGE_TOOLS:
            return 65.0
        if tool_clean in self.EXECUTION_TOOLS:
            return 55.0
        if tool_clean in self.DESTRUCTIVE_FILE_TOOLS:
            return 45.0
        if tool_clean in self.DATABASE_TOOLS:
            return 40.0
        return 20.0

    def _assess_arguments(self, args: dict[str, Any]) -> list[str]:
        signals: list[str] = []
        for key, value in args.items():
            val_str = str(value)

            # Check if touching sensitive paths
            if self.policy.is_sensitive_path(val_str):
                signals.append(f"Sensitive target path in parameter '{key}': {val_str}")

            # Check if blocked destructive commands
            if self.policy.contains_blocked_command(val_str):
                signals.append(f"Catastrophic command signature in parameter '{key}': {val_str}")

            # Check destructive SQL patterns
            for sql_pat in self.compiled_sql:
                m = sql_pat.search(val_str)
                if m:
                    signals.append(f"Destructive database statement in '{key}': {m.group(0)}")

        return signals

    def analyze(self, request: ToolCallRequest) -> DetectorFinding:
        tool_name = request.tool_name
        base_score = self._assess_tool_category(tool_name)
        signals = self._assess_arguments(request.arguments)
        matched_patterns: list[str] = []

        score = base_score

        # If policy explicitly blocks tool
        if self.policy.is_tool_blocked(tool_name):
            matched_patterns.append(f"Tool '{tool_name}' is in active blocked policy list")
            score = 100.0

        # If argument signals contain catastrophic command
        for sig in signals:
            matched_patterns.append(sig)
            if "Catastrophic command" in sig or "Destructive database" in sig:
                score += 50.0
            elif "Sensitive target path" in sig:
                score += 35.0

        # If tool requires mandatory human approval
        if self.policy.does_tool_require_approval(tool_name):
            matched_patterns.append(f"Tool '{tool_name}' marked for mandatory human verification")
            score = max(score, 75.0)

        final_score = min(100.0, score)

        if final_score >= self.policy.config.critical_threshold:
            severity = RiskTier.CRITICAL
            desc = "Critical blast radius: Execution could cause irreversible data loss or privilege escalation."
        elif final_score >= self.policy.config.safe_threshold:
            severity = RiskTier.SUSPICIOUS
            desc = "Moderate blast radius: Requires validation or runtime sandboxing."
        else:
            severity = RiskTier.SAFE
            desc = "Low blast radius: Tool call operates within benign read/compute limits."

        return DetectorFinding(
            detector_name=self.NAME,
            risk_score=final_score,
            severity=severity,
            description=desc,
            matched_patterns=matched_patterns,
            metadata={"base_category_score": base_score, "signals_count": len(signals)},
        )
