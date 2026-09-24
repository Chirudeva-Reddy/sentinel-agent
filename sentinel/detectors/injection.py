"""Detector for Prompt Injection, Jailbreaks, and Malicious Overrides."""

from __future__ import annotations

import base64
import re

from sentinel.core.types import DetectorFinding, RiskTier, ToolCallRequest


class InjectionDetector:
    """Scans tool calls and context for direct/indirect prompt injection signatures."""

    NAME = "prompt_injection_detector"

    # Regex patterns for direct and indirect instruction overrides
    OVERRIDE_PATTERNS = [
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"(?i)disregard\s+(all\s+)?(previous|prior)\s+rules?",
        r"(?i)system\s*override",
        r"(?i)new\s+system\s+prompt\s*:",
        r"(?i)you\s+are\s+now\s+(dan|in\s+developer\s+mode|unfiltered)",
        r"(?i)developer\s+mode\s+enabled",
        r"(?i)from\s+now\s+on\s+you\s+(must|will)\s+bypass",
        r"(?i)do\s+anything\s+now",
        r"(?i)jailbreak(ed)?",
        r"(?i)assistant\s+directive\s*:",
        r"(?i)special\s+instructions?\s+from\s+admin",
    ]

    # Patterns indicating credential exfiltration attempts
    EXFILTRATION_PATTERNS = [
        r"(?i)curl\s+.*?(webhook\.site|burpcollaborator|ngrok\.io|requestbin)",
        r"(?i)(api[_-]?key|secret|token|password|credential)s?\s*(to|into|via)\s*(http|curl|dns|fetch)",
        r"(?i)cat\s+.*?\.(env|aws/credentials|ssh/id_rsa)",
        r"(?i)printenv\s*\|\s*(curl|nc|wget)",
        r"(?i)base64\s+-w\s*0\s+.*?\.(env|ssh)",
    ]

    # Hidden text signatures commonly embedded in crawled web pages
    OBFUSCATION_PATTERNS = [
        r"<!--\s*AI\s*(Instruction|Command|Prompt):.*?-->",
        r"<span[^>]*style=[\"'][^\"']*(display:\s*none|font-size:\s*0|opacity:\s*0)[^\"']*[\"']>.*?<\/span>",
        r"\[\/\/\]:\s*#\s*\(.*?(ignore|override|secret).*?\)",
    ]

    def __init__(self, sensitivity: float = 1.0):
        self.sensitivity = sensitivity
        self.compiled_overrides = [re.compile(p) for p in self.OVERRIDE_PATTERNS]
        self.compiled_exfil = [re.compile(p) for p in self.EXFILTRATION_PATTERNS]
        self.compiled_obfuscation = [re.compile(p) for p in self.OBFUSCATION_PATTERNS]

    def _extract_all_text(self, request: ToolCallRequest) -> str:
        """Flattens all arguments and raw context into a single searchable buffer."""
        chunks: list[str] = [request.tool_name]
        if request.raw_prompt_context:
            chunks.append(request.raw_prompt_context)

        for k, v in request.arguments.items():
            chunks.append(f"{k}: {v}")
        return " \n ".join(chunks)

    def _check_base64_payloads(self, text: str) -> tuple[str, str] | None:
        """Finds base64 encoded strings and checks if decoded contents contain suspicious commands."""
        # Find potential base64 strings of length >= 16
        b64_candidates = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text)
        for cand in b64_candidates:
            try:
                decoded = base64.b64decode(cand, validate=True).decode("utf-8", errors="ignore")
                for pat in self.OVERRIDE_PATTERNS + self.EXFILTRATION_PATTERNS:
                    if re.search(pat, decoded):
                        return cand, decoded
            except Exception:
                continue
        return None

    def analyze(self, request: ToolCallRequest) -> DetectorFinding:
        text = self._extract_all_text(request)
        matched: list[str] = []
        score = 0.0

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

        if final_score >= 70.0:
            severity = RiskTier.CRITICAL
            desc = "High-confidence prompt injection or exfiltration vector detected."
        elif final_score >= 30.0:
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
