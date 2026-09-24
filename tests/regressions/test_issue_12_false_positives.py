"""Issue 12: context-free regexes flagged benign calls; the tool name was scanned as content."""

from __future__ import annotations

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import DecisionAction, ToolCallRequest
from sentinel.detectors.injection import InjectionDetector


def test_tool_name_is_not_scanned_as_content():
    f = InjectionDetector().analyze(ToolCallRequest(tool_name="jailbreak_classifier", arguments={"text": "hi"}))
    assert f.risk_score == 0


def test_research_query_mentioning_jailbreak_is_allowed():
    a = SentinelGateway().inspect(ToolCallRequest(tool_name="search_web", arguments={"query": "jailbreak papers 2025"}))
    assert a.decision == DecisionAction.ALLOW


def test_dev_null_redirect_is_not_injection():
    a = SentinelGateway().inspect(ToolCallRequest(tool_name="execute_bash", arguments={"command": "make > /dev/null"}))
    assert all(f.risk_score < 30 for f in a.findings if f.detector_name == "argument_validator")
