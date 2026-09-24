"""Argument Validator for Shell Injection, Path Traversal, and SSRF."""

from __future__ import annotations

import ipaddress
import posixpath
import re
import socket
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

from sentinel.core.policy import PolicyEngine
from sentinel.core.types import DetectorFinding, RiskTier, ToolCallRequest
from sentinel.normalize import NormalizedCall, normalize, shell_commands

Resolver = Callable[[str], Iterable[str]]
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_URL = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://[^\s'\"<>`]{1,2048}", re.I)
_NET_TOOLS = {"nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "rsync", "curl", "wget", "ftp", "redis-cli"}
_INTERNAL_HOSTNAMES = {"localhost", "localhost.localdomain", "metadata.google.internal", "metadata", "instance-data"}


def parse_ip(host: str) -> IPAddress | None:
    """Parse a URL host as an IP, including the legacy forms libc accepts (2852039166, 0x7f.1, 0177.0.0.1)."""
    host = host.strip("[]")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}", host, re.I):
            return None
        try:
            addr = ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def is_internal(addr: IPAddress) -> bool:
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
        or addr.is_multicast
        or addr in ipaddress.ip_network("100.64.0.0/10")  # CGNAT; also Alibaba metadata
    )


class ArgumentValidator:
    """Detects command injection, path traversal, and SSRF in tool parameters."""

    NAME = "argument_validator"

    _RISKY = r"(cat|ls|rm|curl|wget|nc|ncat|bash|sh|zsh|python3?|perl|eval|whoami|id|base64|env|printenv|chmod)\b"
    CMD_INJECTION_PATTERNS = [
        rf"[;&|]\s*{_RISKY}",  # chaining into a risky program
        rf"\$\(\s*{_RISKY}",  # $(risky ...)
        rf"`\s*{_RISKY}",  # `risky ...`  (plain `code spans` in markdown are fine)
        r"\$\{IFS\}|\$IFS\b",  # whitespace-evasion trick
        r"\b(python3?|perl|ruby|node)\s+-[ec]\b",  # one-liners
    ]

    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"\x00",  # null byte
    ]

    def __init__(self, policy: PolicyEngine | None = None, resolver: Resolver | None = None) -> None:
        """`resolver` maps a hostname to IP strings. Off by default: DNS at check time is slow and racy
        (the tool may resolve differently), so pass one only if you also pin the resolved IP downstream."""
        self.policy = policy or PolicyEngine()
        self.resolver = resolver
        self.compiled_cmd = [re.compile(p, re.IGNORECASE) for p in self.CMD_INJECTION_PATTERNS]
        self.compiled_path = [re.compile(p) for p in self.PATH_TRAVERSAL_PATTERNS]

    def _ssrf_reason(self, url: str) -> str | None:
        try:
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
        except ValueError:
            return f"unparsable URL '{url[:80]}'"
        if not host or host in self.policy.config.allowed_hosts:
            return None
        if host in _INTERNAL_HOSTNAMES or host.endswith((".internal", ".local", ".localhost")):
            return f"internal hostname '{host}'"
        addr = parse_ip(host)
        if addr is not None:
            return f"internal address {addr}" if is_internal(addr) else None
        if self.resolver:
            for ip in self.resolver(host):
                resolved = parse_ip(ip)
                if resolved is not None and is_internal(resolved):
                    return f"'{host}' resolves to internal address {resolved}"
        return None

    def _bare_ip_reasons(self, text: str) -> list[str]:
        """Bare IPs in commands (e.g. `nc 10.0.0.5 4444`). Strict parsing only: '42' is not an IP here."""
        out = []
        for tok in re.findall(r"[0-9a-f:.]{7,45}", text, re.I):
            try:
                addr = ipaddress.ip_address(tok)
            except ValueError:
                continue
            if is_internal(addr) and str(addr) not in self.policy.config.allowed_hosts:
                out.append(f"internal address {addr}")
        return out

    def analyze(self, request: ToolCallRequest | NormalizedCall) -> DetectorFinding:
        call = normalize(request)
        matched: list[str] = []
        score = 0.0

        for key, text in call.args:
            for p in self.compiled_cmd:
                m = p.search(text)
                if m:
                    matched.append(f"Command Injection in '{key}': '{m.group(0)[:80]}'")
                    score += 60.0
            for p in self.compiled_path:
                m = p.search(text)
                if m:
                    matched.append(f"Path Traversal pattern in '{key}': '{m.group(0)!r}'")
                    score += 55.0
            urls = _URL.findall(text)
            reasons = [r for u in urls if (r := self._ssrf_reason(u))]
            if not urls and any(posixpath.basename(argv[0]) in _NET_TOOLS for argv, _ in shell_commands(text)):
                reasons += self._bare_ip_reasons(text)  # only where the IP is a network target, not prose
            for r in dict.fromkeys(reasons):
                matched.append(f"SSRF / internal target in '{key}': {r}")
                score += 70.0

        final_score = min(100.0, score)
        if final_score >= self.policy.config.critical_threshold:
            severity = RiskTier.CRITICAL
            desc = "Critical parameter vulnerability detected (Command Injection, SSRF, or Path Traversal)."
        elif final_score >= self.policy.config.safe_threshold:
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
            metadata={"arguments_checked": [k for k, _ in call.args]},
        )
