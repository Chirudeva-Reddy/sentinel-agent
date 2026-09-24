"""Adapters for integrating SentinelAgent with agent frameworks."""

from sentinel.adapters.mcp_adapter import SentinelMCPMiddleware
from sentinel.adapters.openai_adapter import SentinelOpenAIWrapper

__all__ = [
    "SentinelMCPMiddleware",
    "SentinelOpenAIWrapper",
]
