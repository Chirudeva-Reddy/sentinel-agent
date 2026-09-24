"""Detectors are plugins: adding one needs no gateway change, and a crashing one fails closed."""

from __future__ import annotations

from importlib.metadata import EntryPoint

from sentinel import detectors as registry
from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import DecisionAction, DetectorFinding, RiskTier, ToolCallRequest


class AlwaysCritical:
    NAME = "always_critical"

    def __init__(self, policy):
        self.policy = policy

    def analyze(self, call):
        return DetectorFinding(detector_name=self.NAME, risk_score=99, severity=RiskTier.CRITICAL, description="x")


class Exploding:
    NAME = "exploding"

    def __init__(self, policy):
        pass

    def analyze(self, call):
        raise RuntimeError("boom")


def _with_extra(monkeypatch, target):
    real = registry.entry_points

    def fake(group):
        extra = EntryPoint(name="extra", value=f"{__name__}:{target}", group=group)
        return [*real(group=group), extra]

    monkeypatch.setattr(registry, "entry_points", fake)


def test_builtin_detectors_come_from_entry_points():
    names = {d.NAME for d in SentinelGateway().detectors}
    assert names == {"prompt_injection_detector", "blast_radius_detector", "argument_validator"}


def test_entry_point_detector_runs_without_gateway_change(monkeypatch):
    _with_extra(monkeypatch, "AlwaysCritical")
    a = SentinelGateway().inspect(ToolCallRequest(tool_name="calculator", arguments={"expression": "1"}))
    assert any(f.detector_name == "always_critical" for f in a.findings)
    assert a.decision == DecisionAction.REQUIRE_APPROVAL


def test_crashing_detector_fails_closed(monkeypatch):
    _with_extra(monkeypatch, "Exploding")
    a = SentinelGateway().inspect(ToolCallRequest(tool_name="calculator", arguments={"expression": "1"}))
    err = next(f for f in a.findings if f.detector_name == "exploding")
    assert err.severity == RiskTier.SUSPICIOUS and "boom" in err.description
    assert a.decision != DecisionAction.ALLOW


def test_explicit_detector_list_overrides_registry():
    gw = SentinelGateway(detectors=[AlwaysCritical(None)])
    assert [d.NAME for d in gw.detectors] == ["always_critical"]


def test_duplicate_entry_points_load_once(monkeypatch):
    """Two installed dists registering the same detector (e.g. after a package rename) must not double-count."""
    real = registry.entry_points
    monkeypatch.setattr(registry, "entry_points", lambda group: [*real(group=group), *real(group=group)])
    assert sorted(d.NAME for d in SentinelGateway().detectors) == [
        "argument_validator",
        "blast_radius_detector",
        "prompt_injection_detector",
    ]
