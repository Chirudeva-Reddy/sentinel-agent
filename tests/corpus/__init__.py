"""Attack and benign tool-call corpora. Add cases to the YAML files, not to test code."""

from __future__ import annotations

from pathlib import Path

import yaml

from sentinel.core.types import ToolCallRequest

_DIR = Path(__file__).parent


def load(name: str) -> list[tuple[str, ToolCallRequest]]:
    cases = yaml.safe_load((_DIR / f"{name}.yaml").read_text(encoding="utf-8"))
    return [
        (
            c["id"],
            ToolCallRequest(tool_name=c["tool"], arguments=c.get("args", {}), raw_prompt_context=c.get("context")),
        )
        for c in cases
    ]
