"""Attack and benign tool-call corpora. Add cases to the YAML files, not to test code."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from sentinel.core.types import ToolCallRequest

_DIR = Path(__file__).parent


def cases(name: str) -> list[dict[str, Any]]:
    return yaml.safe_load((_DIR / f"{name}.yaml").read_text(encoding="utf-8"))


def to_request(c: dict[str, Any]) -> ToolCallRequest:
    return ToolCallRequest(tool_name=c["tool"], arguments=c.get("args", {}), raw_prompt_context=c.get("context"))


def load(name: str) -> list[tuple[str, ToolCallRequest]]:
    return [(c["id"], to_request(c)) for c in cases(name)]
