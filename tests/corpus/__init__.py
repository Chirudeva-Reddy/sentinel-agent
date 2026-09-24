"""Corpora live in the package (sentinel/corpus/*.yaml) so `sentinel eval` works from an install."""

from sentinel.eval import cases, load, to_request

__all__ = ["cases", "load", "to_request"]
