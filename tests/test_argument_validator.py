"""Unit tests for ArgumentValidator."""

from __future__ import annotations

from sentinel.core.types import RiskTier, ToolCallRequest
from sentinel.detectors.argument_validator import ArgumentValidator


def test_command_chaining_semicolon():
    validator = ArgumentValidator()
    req = ToolCallRequest(
        tool_name="git_command",
        arguments={"cmd": "git status; rm -rf /"},
    )
    res = validator.analyze(req)
    assert res.risk_score >= 60.0
    assert any("Command Injection" in m for m in res.matched_patterns)


def test_subshell_substitution():
    validator = ArgumentValidator()
    req = ToolCallRequest(
        tool_name="echo_tool",
        arguments={"text": "$(whoami)"},
    )
    res = validator.analyze(req)
    assert res.risk_score >= 60.0
    assert any("Command Injection" in m for m in res.matched_patterns)


def test_path_traversal():
    validator = ArgumentValidator()
    req = ToolCallRequest(
        tool_name="read_file",
        arguments={"path": "../../../../etc/shadow"},
    )
    res = validator.analyze(req)
    assert res.risk_score >= 55.0
    assert any("Path Traversal" in m for m in res.matched_patterns)


def test_ssrf_metadata_service():
    validator = ArgumentValidator()
    req = ToolCallRequest(
        tool_name="fetch_url",
        arguments={"url": "http://169.254.169.254/latest/meta-data/"},
    )
    res = validator.analyze(req)
    assert res.risk_score >= 70.0
    assert res.severity == RiskTier.CRITICAL
    assert any("SSRF" in m for m in res.matched_patterns)
