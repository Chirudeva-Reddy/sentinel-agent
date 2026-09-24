"""Detector for Prompt Injection, Jailbreaks, and Malicious Overrides."""

from __future__ import annotations

import base64
import re

from sentinel.core.policy import PolicyEngine
from sentinel.core.types import DetectorFinding, RiskTier, ToolCallRequest
from sentinel.normalize import NormalizedCall, normalize


class InjectionDetector:
    """Scans tool calls and context for direct/indirect prompt injection signatures."""

    NAME = "prompt_injection_detector"
    SCANS_OUTPUT = True  # also run by gateway.inspect_result on tool outputs

    # Every pattern is bounded ({0,N}) and never requires a distant closing token: an unbounded lazy
    # `.*?-->` rescans the rest of the input from every opener, which is O(n^2) (issue 1).
    OVERRIDE_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"(?i)disregard\s+(all\s+)?(previous|prior)\s+(rules?|instructions?)",
        r"(?i)system\s*override",
        r"(?i)new\s+system\s+prompt\s*:",
        r"(?i)you\s+are\s+(now\s+)?(dan|in\s+developer\s+mode|unfiltered)\b",
        r"(?i)developer\s+mode\s+enabled",
        r"(?i)from\s+now\s+on\s+you\s+(must|will)\s+bypass",
        r"(?i)do\s+anything\s+now",
        r"(?i)assistant\s+directive\s*:",
        r"(?i)special\s+instructions?\s+from\s+admin",
    ]

    EXFILTRATION_PATTERNS = [
        r"(?i)\bcurl\s[^\n]{0,300}?(webhook\.site|burpcollaborator|ngrok\.io|requestbin)",
        r"(?i)(api[_-]?key|secret|token|password|credential)s?\s*(to|into|via)\s*(http|curl|dns|fetch)",
        r"(?i)\bcat\s[^\n]{0,300}?\.(env|aws/credentials|ssh/id_rsa)\b",
        r"(?i)printenv\s*\|\s*(curl|nc|wget)",
        r"(?i)base64\s+-w\s*0\s[^\n]{0,300}?\.(env|ssh)\b",
    ]

    OBFUSCATION_PATTERNS = [
        r"(?i)<!--\s*AI\s*(Instruction|Command|Prompt|Directive)\s*:",
        r"(?i)<[a-z]+\b[^>]{0,500}?style\s*=\s*[\"'][^\"'>]{0,500}?"
        r"(display\s*:\s*none|font-size\s*:\s*0|opacity\s*:\s*0|visibility\s*:\s*hidden)",
        r"(?i)\[//\]:\s*#\s*\([^)\n]{0,500}?(ignore|override|secret)",
    ]

    def __init__(self, policy: PolicyEngine | None = None, sensitivity: float = 1.0) -> None:
        self.policy = policy or PolicyEngine()
        self.sensitivity = sensitivity
        self.compiled_overrides = [re.compile(p) for p in self.OVERRIDE_PATTERNS]
        self.compiled_exfil = [re.compile(p) for p in self.EXFILTRATION_PATTERNS]
        self.compiled_obfuscation = [re.compile(p) for p in self.OBFUSCATION_PATTERNS]

    def _check_base64_payloads(self, text: str) -> tuple[str, str] | None:
        """Finds base64 strings whose decoded contents contain override/exfiltration signatures."""
        for cand in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text)[:50]:
            try:
                decoded = base64.b64decode(cand, validate=True).decode("utf-8", errors="ignore")
            except ValueError:
                continue
            if any(p.search(decoded) for p in self.compiled_overrides + self.compiled_exfil):
                return cand, decoded
        return None

    def analyze(self, request: ToolCallRequest | NormalizedCall) -> DetectorFinding:
        call = normalize(request)
        # Tool name is metadata, not content: scanning it flagged tools like `jailbreak_classifier` (issue 12).
        text = " \n ".join(f"{k}: {v}" for k, v in call.texts())
        matched: list[str] = []
        score = 0.0

        if call.truncated:
            matched.append("Input exceeded size cap and was truncated before scanning")
            score += 40.0

        # Check prompt override patterns
        for p in self.compiled_overrides:
            match = p.search(text)
            if match:
                matched.append(f"Prompt Override: '{match.group(0)}'")
                score += 50.0

        # Check exfiltration patterns
        for p in self.compiled_exfil:
            match = p.search(text)
            if match:
                matched.append(f"Exfiltration Signal: '{match.group(0)}'")
                score += 60.0

        # Check obfuscation patterns
        for p in self.compiled_obfuscation:
            match = p.search(text)
            if match:
                matched.append(f"Hidden HTML/Comment Injection: '{match.group(0)[:60]}...'")
                score += 45.0

        # Check base64 encoded payload
        b64_result = self._check_base64_payloads(text)
        if b64_result:
            cand, dec = b64_result
            matched.append(f"Obfuscated Base64 Injection: '{dec[:50]}...'")
            score += 65.0

        # Cap score at 100.0
        final_score = min(100.0, score * self.sensitivity)

        if final_score >= self.policy.config.critical_threshold:
            severity = RiskTier.CRITICAL
            desc = "High-confidence prompt injection or exfiltration vector detected."
        elif final_score >= self.policy.config.safe_threshold:
            severity = RiskTier.SUSPICIOUS
            desc = "Suspicious prompt override or evasion indicators observed."
        else:
            severity = RiskTier.SAFE
            desc = "No prompt injection signatures detected."

        return DetectorFinding(
            detector_name=self.NAME,
            risk_score=final_score,
            severity=severity,
            description=desc,
            matched_patterns=matched,
            metadata={"text_length": len(text), "matches_count": len(matched)},
        )
