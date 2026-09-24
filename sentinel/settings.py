"""Runtime locations. All mutable state lives under SENTINEL_HOME (default ~/.sentinel), never the CWD."""

from __future__ import annotations

import os
from pathlib import Path


def sentinel_home() -> Path:
    home = Path(os.environ.get("SENTINEL_HOME", Path.home() / ".sentinel")).expanduser()
    home.mkdir(parents=True, exist_ok=True)
    return home
