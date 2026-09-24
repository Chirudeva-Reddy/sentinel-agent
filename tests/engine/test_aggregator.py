"""Aggregation pinned with hand-computed values."""

from __future__ import annotations

import pytest

from sentinel.core.gateway import aggregate


@pytest.mark.parametrize(
    "scores, method, expected",
    [
        ([], "noisy_or", 0.0),
        ([0, 0, 0], "noisy_or", 0.0),
        ([55, 40], "noisy_or", 73.0),  # 1 - .45 * .60
        ([50, 50, 50], "noisy_or", 87.5),  # 1 - .5^3
        ([100, 10], "noisy_or", 100.0),
        ([55, 40], "max", 55.0),
        ([5, 90, 30], "max", 90.0),
    ],
)
def test_aggregate(scores, method, expected):
    assert aggregate(scores, method) == pytest.approx(expected)
