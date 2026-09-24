"""Demonstration: Model Context Protocol (MCP) tool interception."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from sentinel.adapters.mcp_adapter import SentinelMCPMiddleware

console = Console()


def run_demo():
    console.print(
        Panel(
            "[bold yellow]Scenario: Model Context Protocol (MCP) Tool Interception[/bold yellow]\n"
            "An agent connected via MCP requests tool execution.\n"
            "SentinelMCPMiddleware inspects the CallToolRequest in-flight before server dispatch.",
            title="🔌 MCP Middleware Simulation",
            border_style="cyan",
        )
    )

    middleware = SentinelMCPMiddleware()

    # Case 1: Benign MCP Tool Call
    console.print("[bold cyan]Case 1: Safe MCP Tool Call (read_file)[/bold cyan]")
    safe_assessment = middleware.process_call_tool_request(
        name="read_file",
        arguments={"path": "README.md"},
        client_id="claude-desktop-client",
    )
    console.print(
        f"Decision: [green]{safe_assessment.decision.value}[/green] | Score: {safe_assessment.overall_score}/100"
    )

    # Case 2: Dangerous MCP Tool Call with Path Traversal
    console.print("\n[bold red]Case 2: Adversarial MCP Tool Call (Path Traversal)[/bold red]")
    risky_assessment = middleware.process_call_tool_request(
        name="read_file",
        arguments={"path": "../../../../../etc/passwd"},
        client_id="claude-desktop-client",
    )
    console.print(
        f"Decision: [red]{risky_assessment.decision.value}[/red] | Score: {risky_assessment.overall_score}/100"
    )
    console.print(f"Reason: {risky_assessment.reason}")


if __name__ == "__main__":
    run_demo()
