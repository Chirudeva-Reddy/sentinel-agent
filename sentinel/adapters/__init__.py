"""Framework adapters. The MCP proxy (sentinel.adapters.mcp_proxy) needs the [mcp] extra."""

from sentinel.adapters.openai_adapter import SentinelOpenAIWrapper

__all__ = ["SentinelOpenAIWrapper"]
