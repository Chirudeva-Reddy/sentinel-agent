"""Characterisation snapshot: pins (score, decision) for every corpus case.

Any change here must be explained in the PR. Regenerate with SENTINEL_UPDATE_SNAPSHOT=1 pytest tests/characterization.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from sentinel.core.gateway import SentinelGateway
from tests.corpus import load

SNAPSHOT = Path(__file__).with_name("snapshot.json")


def _current() -> dict[str, list]:
    gw = SentinelGateway()
    out = {}
    for corpus in ("attacks", "benign"):
        for case_id, req in load(corpus):
            a = gw.inspect(req)
            out[f"{corpus}/{case_id}"] = [a.overall_score, a.decision.value]
    return out


def test_decisions_match_snapshot():
    current = _current()
    if os.environ.get("SENTINEL_UPDATE_SNAPSHOT"):
        SNAPSHOT.write_text(json.dumps(current, indent=1, sort_keys=True) + "\n")
    expected = json.loads(SNAPSHOT.read_text())
    diff = {k: (expected.get(k), v) for k, v in current.items() if expected.get(k) != v}
    assert not diff, f"decisions changed (expected, got): {json.dumps(diff, indent=1)}"
