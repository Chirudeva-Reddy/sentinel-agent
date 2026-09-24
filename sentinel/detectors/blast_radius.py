"""Blast Radius Estimator for AI Agent Tool Invocations."""

from __future__ import annotations

import posixpath
import re

from sentinel.core.policy import PolicyEngine
from sentinel.core.types import DetectorFinding, RiskTier, ToolCallRequest
from sentinel.normalize import NormalizedCall, normalize, shell_commands

_CREDENTIAL = re.compile(
    r"id_(rsa|ed25519|ecdsa|dsa)\b|\.env\b|\.aws/credentials|/etc/shadow|\.pem\b|\.kube/config", re.I
)
# Programs that run another program. Their own flags and values (sudo -u root, timeout 5, nice -n 10) are skipped.
_WRAPPERS = {
    "sudo", "doas", "env", "nohup", "time", "nice", "command", "exec", "xargs", "timeout", "stdbuf", "ionice",
    "chrt", "taskset", "setsid", "unbuffer", "flock", "runuser", "watch", "strace", "caffeinate",
}  # fmt: skip
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "perl", "ruby", "node"}
_SCRIPT_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}  # take a command string via -c
_RULE_PROGS = {
    "rm",
    "find",
    "dd",
    "shred",
    "chmod",
    "chown",
    "chgrp",
    "wipefs",
    "fdisk",
    "sfdisk",
    "parted",
    "curl",
    "wget",
    "eval",
}
_SYSTEM_DIRS = r"bin|boot|dev|etc|lib|lib64|opt|root|sbin|srv|usr|var|home|users|system|library"
_CRITICAL_TARGET = re.compile(rf"^(/|/\*|~/?\*?|\$\{{?home\}}?/?\*?|\*|\.|\./\*|\.\.|/({_SYSTEM_DIRS})/?\*?)$", re.I)
_MAX_NESTING = 3


def _prog(token: str) -> str:
    return posixpath.basename(token).lower()


def _is_program(token: str) -> bool:
    p = _prog(token)
    return p in _RULE_PROGS or p in _SHELLS or p in _WRAPPERS or p.startswith("mkfs")


def _strip_wrappers(argv: list[str]) -> list[str]:
    """Drop VAR=val assignments and wrapper programs (with their flags) to reach the command that runs."""
    i = 0
    while i < len(argv):
        if "=" in argv[i] and not argv[i].startswith("-"):
            i += 1
        elif _prog(argv[i]) in _WRAPPERS:
            nxt = next((k for k in range(i + 1, len(argv)) if _is_program(argv[k])), None)
            if nxt is None:
                return argv[i:]  # wraps something we have no rule for
            i = nxt
        else:
            break
    return argv[i:]


def _nested_script(argv: list[str]) -> str | None:
    """The command string an `sh -c '...'` / `bash -lc '...'` / `eval ...` will run, if any."""
    prog = _prog(argv[0])
    if prog == "eval":
        return " ".join(argv[1:])
    if prog in _SCRIPT_SHELLS:
        for k, a in enumerate(argv[1:], start=1):
            if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                return argv[k + 1] if k + 1 < len(argv) else None
    return None


def _flags(argv: list[str]) -> set[str]:
    out: set[str] = set()
    for a in argv[1:]:
        if a.startswith("--"):
            out.add(a)
        elif a.startswith("-") and len(a) > 1:
            out.update(f"-{c}" for c in a[1:])
    return out


def catastrophic_reason(argv: list[str], next_argv: list[str] | None, op: str | None) -> str | None:
    """Return why a single simple command is catastrophic, or None."""
    argv = _strip_wrappers(argv)
    if not argv:
        return None
    prog = posixpath.basename(argv[0]).lower()
    flags = _flags(argv)
    targets = [a for a in argv[1:] if not a.startswith("-")]
    critical_targets = [t for t in targets if _CRITICAL_TARGET.match(t)]

    if prog == "rm" and flags & {"-r", "-R", "--recursive"} and critical_targets:
        return f"recursive rm of {critical_targets[0]}"
    if prog == "find":
        roots = [a for a in argv[1:] if not a.startswith("-")][:1]
        destructive = "-delete" in argv or any(
            a in ("-exec", "-execdir") and i + 1 < len(argv) and posixpath.basename(argv[i + 1]) in ("rm", "shred")
            for i, a in enumerate(argv)
        )
        if destructive and roots and _CRITICAL_TARGET.match(roots[0]):
            return f"find {roots[0]} with deletion"
    if prog.startswith("mkfs") or prog in ("wipefs", "fdisk", "sfdisk", "parted"):
        return f"filesystem/partition tool {prog}"
    if prog == "dd" and any(a.startswith("of=/dev/") for a in argv):
        return "dd onto a block device"
    if prog == "shred" and any(t.startswith("/dev/") for t in targets):
        return "shred of a block device"
    if prog in ("chmod", "chown", "chgrp") and flags & {"-R", "--recursive"} and critical_targets:
        return f"recursive {prog} of {critical_targets[0]}"
    if prog in ("curl", "wget") and op == "|" and next_argv:
        nxt = _strip_wrappers(next_argv)
        if nxt and posixpath.basename(nxt[0]) in _SHELLS:
            return f"remote script piped into {nxt[0]}"
    return None


def catastrophic_commands(text: str, depth: int = 0) -> list[str]:
    reasons = []
    if ":(){" in text.replace(" ", ""):
        reasons.append("fork bomb")
    cmds = [(_strip_wrappers(argv), op) for argv, op in shell_commands(text)]
    for i, (argv, op) in enumerate(cmds):
        if not argv:
            continue
        script = _nested_script(argv)
        if script and depth < _MAX_NESTING:
            reasons += [f"{r} (inside {_prog(argv[0])})" for r in catastrophic_commands(script, depth + 1)]
        nxt = cmds[i + 1][0] if i + 1 < len(cmds) else None
        r = catastrophic_reason(argv, nxt, op)
        if r:
            reasons.append(r)
    return reasons


class BlastRadiusDetector:
    """Computes the potential operational damage (blast radius) of executing a tool call."""

    NAME = "blast_radius_detector"

    # Category base risks
    EXECUTION_TOOLS = {"execute_bash", "shell", "run_command", "terminal", "eval", "exec", "python_exec", "run_shell"}
    DESTRUCTIVE_FILE_TOOLS = {"delete_file", "remove_directory", "truncate_file", "unlink"}
    DATABASE_TOOLS = {"execute_sql", "query_database", "run_db_migration"}
    PRIVILEGE_TOOLS = {"transfer_funds", "make_payment", "grant_role", "revoke_access", "change_password"}
    READ_ONLY_TOOLS = {"read_file", "view_file", "search_web", "list_directory", "calculator", "get_weather"}

    SQL_DESTRUCTIVE_PATTERNS = [
        r"(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA|VIEW)\b",
        r"(?i)\bTRUNCATE\s+TABLE\b",
        r"(?i)\bDELETE\s+FROM\s+\w+\s*(;|$)",  # DELETE without WHERE clause
        r"(?i)\bALTER\s+TABLE\s+[^;]{0,200}?\bDROP\b",
        r"(?i)\bGRANT\s+ALL\b",
    ]

    def __init__(self, policy: PolicyEngine | None = None) -> None:
        self.policy = policy or PolicyEngine()
        self.compiled_sql = [re.compile(p) for p in self.SQL_DESTRUCTIVE_PATTERNS]

    def _assess_tool_category(self, tool: str) -> float:
        if tool in self.READ_ONLY_TOOLS:
            return 5.0
        if tool in self.PRIVILEGE_TOOLS:
            return 65.0
        if tool in self.EXECUTION_TOOLS:
            return 55.0
        if tool in self.DESTRUCTIVE_FILE_TOOLS:
            return 45.0
        if tool in self.DATABASE_TOOLS:
            return 25.0  # below safe_threshold: a SELECT is fine; destructive SQL signals add on top
        return 20.0

    def analyze(self, request: ToolCallRequest | NormalizedCall) -> DetectorFinding:
        call = normalize(request)
        base_score = self._assess_tool_category(call.tool)
        score = base_score
        matched: list[str] = []

        if self.policy.is_tool_blocked(call.tool):
            matched.append(f"Tool '{call.tool}' is in active blocked policy list")
            score = 100.0

        for key, text in call.args:
            if self.policy.is_sensitive_path(text):
                matched.append(f"Sensitive target path in parameter '{key}': {text[:120]}")
                # Credential material (keys, .env, cloud creds, shadow) is a human decision on its own.
                score = (
                    max(score + 35.0, self.policy.config.critical_threshold)
                    if _CREDENTIAL.search(text)
                    else score + 35.0
                )
            reasons = catastrophic_commands(text)
            if self.policy.contains_blocked_command(text):
                reasons.append("policy blocked_commands signature")
            for r in reasons:
                matched.append(f"Catastrophic command in parameter '{key}': {r}")
                score = 100.0
            for pat in self.compiled_sql:
                m = pat.search(text)
                if m:
                    matched.append(f"Destructive database statement in '{key}': {m.group(0)}")
                    score += 50.0

        if self.policy.does_tool_require_approval(call.tool):
            matched.append(f"Tool '{call.tool}' marked for mandatory human verification")

        final_score = min(100.0, score)
        if final_score >= self.policy.config.critical_threshold:
            severity = RiskTier.CRITICAL
            desc = "Critical blast radius: Execution could cause irreversible data loss or privilege escalation."
        elif final_score >= self.policy.config.safe_threshold:
            severity = RiskTier.SUSPICIOUS
            desc = "Moderate blast radius: Requires validation or runtime sandboxing."
        else:
            severity = RiskTier.SAFE
            desc = "Low blast radius: Tool call operates within benign read/compute limits."

        return DetectorFinding(
            detector_name=self.NAME,
            risk_score=final_score,
            severity=severity,
            description=desc,
            matched_patterns=matched,
            metadata={"base_category_score": base_score},
        )
