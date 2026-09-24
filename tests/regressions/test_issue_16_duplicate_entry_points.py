"""Issue 16: stale install metadata registered every detector twice and noisy-OR double-counted it."""

from __future__ import annotations

from sentinel import detectors as registry
from sentinel.core.gateway import SentinelGateway


def test_duplicate_entry_points_load_once(monkeypatch):
    real = registry.entry_points
    monkeypatch.setattr(registry, "entry_points", lambda group: [*real(group=group), *real(group=group)])
    assert sorted(d.NAME for d in SentinelGateway().detectors) == [
        "argument_validator",
        "blast_radius_detector",
        "prompt_injection_detector",
    ]
