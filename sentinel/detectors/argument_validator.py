"""Argument Validator for Shell Injection, Path Traversal, and SSRF."""

from __future__ import annotations

import re

from sentinel.core.types import DetectorFinding, RiskTier, ToolCallRequest


class ArgumentValidator:
    """Detects command injection, path traversal, and SSRF in tool parameters."""

    NAME = "argument_validator"

    # Command chaining and subshell execution
    CMD_INJECTION_PATTERNS = [
        r"[;&|`]\s*(cat|ls|rm|curl|wget|nc|bash|sh|python|eval|whoami|id)\b",
        r"\$\([^\)]+\)",  # Command substitution $(...)
        r"`[^`]+`",  # Backtick substitution `...`
        r"\$\{[^}]+\}",  # Variable expansion ${...}
        r"\b(python|perl|ruby|node)\s+-e\b",  # One-liner execution
        r">\s*/dev/null",  # Output redirection hiding
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",  # Relative path ../
        r"\.\.\\",  # Windows ..\
        r"%2e%2e%2f",  # URL encoded ../
        r"%252e%252e%252f",  # Double encoded
        r"\0",  # Null byte injection
    ]

    # Cloud Metadata & SSRF targeting
    SSRF_PATTERNS = [
        r"169\.254\.169\.254",  # AWS / GCP / Azure IMDS
        r"metadata\.google\.internal",  # GCP metadata
        r"127\.0\.0\.1",  # Localhost
        r"localhost",
        r"0\.0\.0\.0",
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Private IP range
        r"192\.168\.\d{1,3}\.\d{1,3}",  # Private IP range
    ]

    def __init__(self):
        self.compiled_cmd = [re.compile(p, re.IGNORECASE) for p in self.CMD_INJECTION_PATTERNS]
        self.compiled_path = [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS]
        self.compiled_ssrf = [re.compile(p, re.IGNORECASE) for p in self.SSRF_PATTERNS]

    def analyze(self, request: ToolCallRequest) -> DetectorFinding:
        matched: list[str] = []
        score = 0.0

        for key, val in request.arguments.items():
            val_str = str(val)

            # Check Command Injection
            for p in self.compiled_cmd:
                m = p.search(val_str)
                if m:
                    matched.append(f"Command Injection in '{key}': '{m.group(0)}'")
                    score += 60.0

            # Check Path Traversal
            for p in self.compiled_path:
                m = p.search(val_str)
                if m:
                    matched.append(f"Path Traversal pattern in '{key}': '{m.group(0)}'")
                    score += 55.0

            # Check SSRF / Private IP Targeting
            for p in self.compiled_ssrf:
                m = p.search(val_str)
                if m:
                    matched.append(f"SSRF / Cloud Metadata target in '{key}': '{m.group(0)}'")
                    score += 70.0

        final_score = min(100.0, score)

        if final_score >= 70.0:
            severity = RiskTier.CRITICAL
            desc = "Critical parameter vulnerability detected (Command Injection, SSRF, or Path Traversal)."
        elif final_score >= 30.0:
            severity = RiskTier.SUSPICIOUS
            desc = "Potential argument tampering or suspicious path formatting detected."
        else:
            severity = RiskTier.SAFE
            desc = "Tool arguments conform to standard syntactic expectations."

        return DetectorFinding(
            detector_name=self.NAME,
            risk_score=final_score,
            severity=severity,
            description=desc,
            matched_patterns=matched,
            metadata={"arguments_checked": list(request.arguments.keys())},
        )
