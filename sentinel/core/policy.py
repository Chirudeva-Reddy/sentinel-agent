"""Security Policy Management for SentinelAgent."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml

from sentinel.core.types import PolicyConfig
from sentinel.normalize import fold_tool_name


class PolicyEngine:
    """Evaluates requests against declared security policy."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or self.load_default()

    @classmethod
    def load_default(cls) -> PolicyConfig:
        return PolicyConfig.model_validate({})

    @classmethod
    def from_profile(cls, name: str) -> PolicyEngine:
        """Packaged profiles: default, dev, strict (sentinel/policies/<name>.yaml)."""
        text = files("sentinel.policies").joinpath(f"{name}.yaml").read_text("utf-8")
        return cls(PolicyConfig(**(yaml.safe_load(text) or {})))

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyEngine:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(PolicyConfig(**data))

    @staticmethod
    def _in(tool_name: str, tools: list[str]) -> bool:
        return fold_tool_name(tool_name) in {fold_tool_name(t) for t in tools}

    def is_tool_blocked(self, tool_name: str) -> bool:
        return self._in(tool_name, self.config.blocked_tools)

    def does_tool_require_approval(self, tool_name: str) -> bool:
        return self._in(tool_name, self.config.require_approval_tools)

    def is_tool_known(self, tool_name: str) -> bool:
        c = self.config
        return self._in(tool_name, c.allowed_tools + c.require_approval_tools + c.blocked_tools)

    def is_sensitive_path(self, target_path: str) -> bool:
        target = target_path.strip().lower()
        for sensitive in self.config.sensitive_paths:
            s_clean = sensitive.strip().lower()
            if s_clean in target or target.endswith(s_clean):
                return True
        return False

    def contains_blocked_command(self, cmd_string: str) -> bool:
        cmd_lower = cmd_string.lower().strip()
        for blocked in self.config.blocked_commands:
            if blocked.lower() in cmd_lower:
                return True
        return False
