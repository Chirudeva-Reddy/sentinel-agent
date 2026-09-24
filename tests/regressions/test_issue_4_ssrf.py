"""Issue 4: SSRF checks matched URL text, so alternate IP encodings and ranges slipped through."""

from __future__ import annotations

import pytest

from sentinel.core.policy import PolicyEngine
from sentinel.core.types import PolicyConfig, RiskTier, ToolCallRequest
from sentinel.detectors.argument_validator import ArgumentValidator

INTERNAL = [
    "http://2852039166/latest/meta-data/",  # 169.254.169.254 as decimal
    "http://0xA9FEA9FE/",  # hex
    "http://0251.0376.0251.0376/",  # octal
    "http://[::1]:8080/",
    "http://[::ffff:169.254.169.254]/",
    "http://172.16.0.5/admin",
    "http://172.31.255.255/",
    "http://[fd00::1]/",
    "http://127.1/",
    "http://0.0.0.0:9200/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "gopher://10.0.0.1:6379/_FLUSHALL",
]


@pytest.mark.parametrize("url", INTERNAL)
def test_internal_targets_are_critical(url):
    f = ArgumentValidator().analyze(ToolCallRequest(tool_name="fetch_url", arguments={"url": url}))
    assert f.severity == RiskTier.CRITICAL, url


@pytest.mark.parametrize("url", ["https://docs.python.org/3/", "http://172.32.0.1/", "https://8.8.8.8/"])
def test_public_targets_are_clean(url):
    f = ArgumentValidator().analyze(ToolCallRequest(tool_name="fetch_url", arguments={"url": url}))
    assert f.risk_score == 0, (url, f.matched_patterns)


def test_dns_name_resolving_to_private_address_via_resolver():
    v = ArgumentValidator(resolver=lambda host: ["10.1.2.3"] if host == "evil.example" else [])
    f = v.analyze(ToolCallRequest(tool_name="fetch_url", arguments={"url": "http://evil.example/"}))
    assert f.severity == RiskTier.CRITICAL


def test_policy_allowed_hosts_exempt_dev_servers():
    policy = PolicyEngine(PolicyConfig(allowed_hosts=["localhost"]))
    f = ArgumentValidator(policy).analyze(
        ToolCallRequest(tool_name="fetch_url", arguments={"url": "http://localhost:3000/health"})
    )
    assert f.risk_score == 0
