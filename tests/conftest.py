"""Shared fixtures. No test may write to the repo: all state goes to a per-test SENTINEL_HOME."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_sentinel_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_HOME", str(tmp_path / "sentinel-home"))
