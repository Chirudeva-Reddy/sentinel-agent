"""Detector plugins.

A detector is any class with a NAME, an `__init__(policy)` and `analyze(call: NormalizedCall) -> DetectorFinding`,
registered under the `sentinel.detectors` entry-point group:

    [project.entry-points."sentinel.detectors"]
    my_detector = "my_pkg.module:MyDetector"
"""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Protocol

from sentinel.core.types import DetectorFinding

if TYPE_CHECKING:
    from sentinel.core.policy import PolicyEngine
    from sentinel.normalize import NormalizedCall

GROUP = "sentinel.detectors"


class Detector(Protocol):
    NAME: str

    def analyze(self, call: NormalizedCall) -> DetectorFinding: ...


def load_detectors(policy: PolicyEngine) -> list[Detector]:
    eps = sorted(entry_points(group=GROUP), key=lambda ep: ep.name)
    if not eps:
        # Fail closed: a gateway with no detectors would allow everything.
        raise RuntimeError(f"No detectors registered under '{GROUP}'. Is sentinel-agent installed (pip install -e .)?")
    return [ep.load()(policy) for ep in eps]


__all__ = ["GROUP", "Detector", "load_detectors"]
