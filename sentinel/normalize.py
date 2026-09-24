"""Canonicalises a tool call once, so every detector sees the same bounded, decoded view.

Detectors must read NormalizedCall, never the raw request: this is where the input size cap,
Unicode folding and URL decoding live, so an evasion fixed here is fixed for every detector.
"""

from __future__ import annotations

import re
import shlex
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from sentinel.core.types import ToolCallRequest

MAX_INPUT_CHARS = 64_000
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"))


@dataclass(frozen=True)
class NormalizedCall:
    tool: str
    """Case-folded, stripped tool name. Metadata only: never scan it as content."""
    args: list[tuple[str, str]]
    """(dotted.key.path, normalised string) for every leaf value, nested structures flattened."""
    context: str | None
    truncated: bool = False
    raw: ToolCallRequest | None = field(default=None, compare=False)

    def texts(self) -> list[tuple[str, str]]:
        """All scannable content: argument leaves plus the prompt context."""
        return self.args + ([("context", self.context)] if self.context else [])


def fold_tool_name(name: str) -> str:
    """The one way tool names are compared everywhere (policy lists, detectors, approval digests)."""
    return unicodedata.normalize("NFKC", name).strip().lower()


def canonical_text(s: str) -> str:
    """NFKC + zero-width strip + URL-decode to a fixed point (bounded)."""
    s = unicodedata.normalize("NFKC", s).translate(_ZERO_WIDTH)
    for _ in range(3):  # %252e -> %2e -> .
        decoded = unquote(s)
        if decoded == s:
            break
        s = decoded
    return s


def _leaves(value: Any, path: str) -> list[tuple[str, str]]:
    if isinstance(value, dict):
        return [leaf for k, v in value.items() for leaf in _leaves(v, f"{path}.{k}" if path else str(k))]
    if isinstance(value, (list, tuple)):
        return [leaf for i, v in enumerate(value) for leaf in _leaves(v, f"{path}[{i}]")]
    return [(path, value if isinstance(value, str) else str(value))]


def normalize(req: ToolCallRequest | NormalizedCall) -> NormalizedCall:
    if isinstance(req, NormalizedCall):
        return req
    budget = MAX_INPUT_CHARS
    truncated = False
    args: list[tuple[str, str]] = []
    for key, text in _leaves(req.arguments, ""):
        if len(text) > budget:
            text, truncated = text[:budget], True
        budget -= len(text)
        args.append((key, canonical_text(text)))
    context = req.raw_prompt_context
    if context is not None:
        if len(context) > budget:
            context, truncated = context[: max(budget, 0)], True
        context = canonical_text(context)
    return NormalizedCall(
        tool=fold_tool_name(req.tool_name),
        args=args,
        context=context,
        truncated=truncated,
        raw=req,
    )


# --- shell parsing -------------------------------------------------------------------------------

_SUBSHELL = re.compile(r"\$\(|`|\)")
_SEPARATORS = {";", "|", "||", "&", "&&", "\n"}


def shell_commands(text: str) -> list[tuple[list[str], str | None]]:
    """Split a string into simple commands as (argv, operator-that-follows).

    Subshells ($(...) and backticks) are flattened into top-level commands so their contents are
    checked too. ponytail: shlex, not a full bash grammar; bashlex if heredocs/functions matter.
    """
    flat = _SUBSHELL.sub(" ; ", text.replace("\n", " ; "))
    lexer = shlex.shlex(flat, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:  # unbalanced quotes: fall back to whitespace so we still see the words
        tokens = re.split(r"\s+|(?<=[;&|])|(?=[;&|])", flat)
    out: list[tuple[list[str], str | None]] = []
    argv: list[str] = []
    for tok in tokens:
        if tok in _SEPARATORS:
            if argv:
                out.append((argv, tok))
            argv = []
        elif tok:
            argv.append(tok)
    if argv:
        out.append((argv, None))
    return out
