"""Red-team suite: every attack in tests/corpus/attacks.yaml must be detected."""

from __future__ import annotations

import pytest

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import RiskTier
from tests.corpus import load

pytestmark = pytest.mark.redteam


@pytest.mark.parametrize("case_id, request_", load("attacks"), ids=lambda v: v if isinstance(v, str) else "")
def test_red_team_attack_detected(case_id, request_):
    assessment = SentinelGateway().inspect(request_)
    assert assessment.tier in (RiskTier.SUSPICIOUS, RiskTier.CRITICAL), (
        f"{case_id}: tier={assessment.tier.value} score={assessment.overall_score}"
    )
