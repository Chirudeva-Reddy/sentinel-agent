"""Per-session taint tracking for tool outputs (information-flow idea from CaMeL / FIDES, much simplified).

Untrusted tool output (web pages, emails, files) is fingerprinted as fixed-width character shingles.
A later call whose arguments contain one of those shingles carries that taint. A session that has seen
an injection attempt in untrusted output is marked compromised.

ponytail: substring matching only. It stops copy-paste exfiltration and "do what the page said"
flows; paraphrased or re-encoded exfiltration gets past it. It raises the bar, it does not solve it.
Memory is O(untrusted chars) per session in-process; move to a TTL cache/Redis for long-lived servers.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

_WS = re.compile(r"\s+")


def _canon(text: str) -> str:
    return _WS.sub(" ", text).strip().lower()


def _shingles(text: str, width: int) -> set[int]:
    t = _canon(text)
    return {hash(t[i : i + width]) for i in range(len(t) - width + 1)}


@dataclass
class _Session:
    fingerprints: dict[int, str] = field(default_factory=dict)  # shingle hash -> source tool
    compromised_by: str | None = None


@dataclass(frozen=True)
class TaintHit:
    source: str
    reason: str


class TaintTracker:
    def __init__(self, min_match: int = 20) -> None:
        self.min_match = min_match
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()

    def label(self, session_id: str, source_tool: str, text: str, injection: bool = False) -> None:
        """Record untrusted output from `source_tool`."""
        prints = _shingles(text, self.min_match)
        with self._lock:
            s = self._sessions.setdefault(session_id, _Session())
            for h in prints:
                s.fingerprints.setdefault(h, source_tool)
            if injection and not s.compromised_by:
                s.compromised_by = source_tool

    def check(self, session_id: str, texts: list[str]) -> list[TaintHit]:
        """Why these argument texts are tainted in this session (empty list = clean)."""
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                return []
            hits = []
            if s.compromised_by:
                hits.append(
                    TaintHit(s.compromised_by, f"session saw an injection attempt in '{s.compromised_by}' output")
                )
            for text in texts:
                for h in _shingles(text, self.min_match):
                    if h in s.fingerprints:
                        src = s.fingerprints[h]
                        hits.append(TaintHit(src, f"argument copies untrusted text from '{src}' output"))
                        break
            return hits

    def forget(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)
