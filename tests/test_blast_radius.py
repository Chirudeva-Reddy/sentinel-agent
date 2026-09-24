"""Unit tests for BlastRadiusDetector."""

from __future__ import annotations

from sentinel.core.policy import PolicyEngine
from sentinel.core.types import RiskTier, ToolCallRequest
from sentinel.detectors.blast_radius import BlastRadiusDetector


def test_benign_read_only_tool():
    policy = PolicyEngine()
    detector = BlastRadiusDetector(policy)
    req = ToolCallRequest(
        tool_name="read_file",
        arguments={"path": "package.json"},
    )
    res = detector.analyze(req)
    assert res.risk_score <= 30.0
    assert res.severity == RiskTier.SAFE


def test_destructive_rm_rf():
    policy = PolicyEngine()
    detector = BlastRadiusDetector(policy)
    req = ToolCallRequest(
        tool_name="execute_bash",
        arguments={"command": "rm -rf /"},
    )
    res = detector.analyze(req)
    assert res.risk_score >= 90.0
    assert res.severity == RiskTier.CRITICAL
    assert any("Catastrophic command" in m for m in res.matched_patterns)


def test_sensitive_path_env_access():
    policy = PolicyEngine()
    detector = BlastRadiusDetector(policy)
    req = ToolCallRequest(
        tool_name="read_file",
        arguments={"file_path": "/var/secrets/.env"},
    )
    res = detector.analyze(req)
    assert res.risk_score >= 35.0
    assert any("Sensitive target path" in m for m in res.matched_patterns)


def test_sql_drop_table():
    policy = PolicyEngine()
    detector = BlastRadiusDetector(policy)
    req = ToolCallRequest(
        tool_name="execute_sql",
        arguments={"query": "DROP TABLE users CASCADE;"},
    )
    res = detector.analyze(req)
    assert res.risk_score >= 70.0
    assert res.severity == RiskTier.CRITICAL
    assert any("Destructive database" in m for m in res.matched_patterns)
