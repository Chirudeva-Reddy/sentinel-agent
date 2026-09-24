"""Issue 1: crafted input caused catastrophic regex backtracking (48 s for one call)."""

from __future__ import annotations

import time

import pytest

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import RiskTier, ToolCallRequest

PATHOLOGICAL_PREFIXES = [
    '<span style="display:none">',
    "<!-- AI Instruction:",
    "[//]: # (",
    "curl ",
    "cat ",
    "base64 -w0 ",
    "$(",
    "${",
    "A" * 15 + "=",
]


@pytest.mark.parametrize("prefix", PATHOLOGICAL_PREFIXES)
def test_repeated_prefix_is_linear(prefix):
    payload = prefix * (64_000 // len(prefix))
    t0 = time.perf_counter()
    SentinelGateway().inspect(ToolCallRequest(tool_name="read_file", arguments={"x": payload}))
    assert time.perf_counter() - t0 < 1.0


def test_original_reproduction():
    payload = '<span style="display:none">' * 20_000
    t0 = time.perf_counter()
    SentinelGateway().inspect(ToolCallRequest(tool_name="read_file", arguments={"x": payload}))
    assert time.perf_counter() - t0 < 1.0


def test_oversized_input_is_flagged_not_ignored():
    a = SentinelGateway().inspect(ToolCallRequest(tool_name="read_file", arguments={"x": "a" * 200_000}))
    assert a.tier != RiskTier.SAFE
    assert any("truncated" in m for f in a.findings for m in f.matched_patterns)
