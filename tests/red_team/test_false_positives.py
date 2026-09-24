"""Benign corpus: a decision stricter than the case's `expect` (default ALLOW) is a false positive."""

from __future__ import annotations

from sentinel.core.gateway import _RANK, SentinelGateway
from sentinel.core.types import DecisionAction
from tests.corpus import cases, to_request

MAX_FP_RATE = 0.05


def test_benign_false_positive_rate():
    gw = SentinelGateway()
    corpus = cases("benign")
    fps = []
    for c in corpus:
        got = gw.inspect(to_request(c)).decision
        expect = DecisionAction(c.get("expect", "ALLOW"))
        if _RANK[got] > _RANK[expect]:
            fps.append(f"{c['id']}: expected {expect.value}, got {got.value}")
    assert len(corpus) >= 50
    assert len(fps) / len(corpus) <= MAX_FP_RATE, "\n".join(fps)
