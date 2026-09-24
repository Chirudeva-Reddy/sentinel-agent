"""Exactly one default policy, strict schema, and packaged profiles."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinel.core.policy import PolicyEngine
from sentinel.core.types import DecisionAction, PolicyConfig


def test_policyconfig_defaults_are_the_default_policy():
    assert PolicyConfig() == PolicyEngine.load_default()


def test_unknown_keys_are_rejected(tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text("safe_threshold: 30\nsafe_treshold: 10\n")
    with pytest.raises(ValidationError):
        PolicyEngine.from_file(p)


def test_threshold_order_is_validated():
    with pytest.raises(ValidationError):
        PolicyConfig(safe_threshold=80, critical_threshold=70)


def test_unknown_tool_action_cannot_be_allow():
    with pytest.raises(ValidationError):
        PolicyConfig(unknown_tool_action=DecisionAction.ALLOW)


@pytest.mark.parametrize("name", ["default", "dev", "strict"])
def test_packaged_profiles_load(name):
    assert PolicyEngine.from_profile(name).config.version


def test_dev_profile_allows_localhost():
    assert "localhost" in PolicyEngine.from_profile("dev").config.allowed_hosts
