"""Model Context Protocol (MCP) Security Middleware Adapter."""

from __future__ import annotations

from typing import Any

from sentinel.core.gateway import SentinelGateway
from sentinel.core.types import RiskAssessment, ToolCallRequest


class SentinelMCPMiddleware:
    """Zero-Trust Middleware for Model Context Protocol (MCP) servers and clients."""

    def __init__(self, gateway: SentinelGateway | None = None):
        self.gateway = gateway or SentinelGateway()

    def process_call_tool_request(
        self,
        name: str,
        arguments: dict[str, Any],
        client_id: str = "mcp-client",
    ) -> RiskAssessment:
        """Inspects an MCP CallToolRequest before dispatching to MCP tool handlers."""
        tool_req = ToolCallRequest(
            tool_name=name,
            arguments=arguments,
            agent_id=client_id,
        )
        return self.gateway.inspect(tool_req)
