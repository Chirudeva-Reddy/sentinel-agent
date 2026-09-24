"""Issue 19: internal targets without a URL scheme skipped the SSRF check (the old regex caught them)."""

from __future__ import annotations

import pytest

from sentinel.core.types import RiskTier, ToolCallRequest
from sentinel.detectors.argument_validator import ArgumentValidator


@pytest.mark.parametrize(
    "target",
    [
        "169.254.169.254/latest/meta-data/",
        "localhost:6379",
        "//169.254.169.254/x",
        "10.0.0.5",
        "2852039166/latest",
        "[::1]:8080",
    ],
)
def test_schemeless_internal_target_is_critical(target):
    f = ArgumentValidator().analyze(ToolCallRequest(tool_name="fetch_url", arguments={"url": target}))
    assert f.severity == RiskTier.CRITICAL, target


@pytest.mark.parametrize(
    "value", ["docs.python.org/3/", "42", "SSRF 169.254.169.254 explained", "8.8.8.8", "v1.2.3", "3.14"]
)
def test_prose_numbers_and_public_hosts_stay_clean(value):
    f = ArgumentValidator().analyze(ToolCallRequest(tool_name="fetch_url", arguments={"q": value}))
    assert f.risk_score == 0, (value, f.matched_patterns)
