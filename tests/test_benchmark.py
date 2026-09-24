"""Latency benchmark. Runs in its own CI job (pytest -m benchmark), not in the unit suite."""

from __future__ import annotations

import pytest

from sentinel.core.gateway import SentinelGateway
from tests.corpus import load

pytestmark = pytest.mark.benchmark


def test_inspect_latency(benchmark):
    gw = SentinelGateway()
    requests = [r for _, r in load("attacks") + load("benign")]
    benchmark(lambda: [gw.inspect(r) for r in requests])
