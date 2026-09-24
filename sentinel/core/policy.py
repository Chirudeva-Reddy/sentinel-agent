"""Security Policy Management for SentinelAgent."""

from __future__ import annotations

from pathlib import Path

import yaml

from sentinel.core.types import PolicyConfig

DEFAULT_POLICY_YAML = """
version: "1.0"
safe_threshold: 30.0
critical_threshold: 70.0

# Tools not listed anywhere below get this decision floor (deny by default).
unknown_tool_action: "REQUIRE_APPROVAL"

# Hosts exempt from SSRF checks. Empty in the default policy; a dev policy might add "localhost".
allowed_hosts: []

# Known tools. Detectors still run on their arguments; listing a tool only lifts the unknown-tool floor.
allowed_tools:
  - "read_file"
  - "view_file"
  - "write_file"
  - "search_web"
  - "list_directory"
  - "calculator"
  - "get_weather"
  - "summarize_text"
  - "translate_text"
  - "fetch_url"
  - "execute_sql"
  - "query_database"

blocked_tools:
  - "bypass_security"
  - "dump_credentials"
  - "arbitrary_eval"

require_approval_tools:
  - "execute_bash"
  - "shell"
  - "run_command"
  - "run_shell"
  - "terminal"
  - "delete_file"
  - "drop_database"
  - "transfer_funds"
  - "send_email"
  - "git_push_force"

sensitive_paths:
  - "/etc/passwd"
  - "/etc/shadow"
  - "~/.ssh"
  - "~/.aws"
  - ".env"
  - "id_rsa"
  - "id_ed25519"
  - "/var/run/docker.sock"

# Extra substring signatures. Destructive shell commands (rm -r /, find / -delete, mkfs, dd of=/dev,
# curl | sh, fork bombs) are detected by parsing argv in BlastRadiusDetector, not listed here.
blocked_commands: []
"""


class PolicyEngine:
    """Evaluates requests against declared security policy."""

    def __init__(self, config: PolicyConfig | None = None):
        self.config = config or self.load_default()

    @classmethod
    def load_default(cls) -> PolicyConfig:
        data = yaml.safe_load(DEFAULT_POLICY_YAML)
        return PolicyConfig(**data)

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyEngine:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls(PolicyConfig(**data))

    @staticmethod
    def _fold(tool_name: str) -> str:
        return tool_name.strip().lower()

    def _in(self, tool_name: str, tools: list[str]) -> bool:
        return self._fold(tool_name) in {self._fold(t) for t in tools}

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
