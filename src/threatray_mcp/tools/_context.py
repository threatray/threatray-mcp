"""Helper to retrieve the ThreatrayClient from a FastMCP request context."""

from fastmcp import Context

from ..client import ThreatrayClient


def get_client(ctx: Context) -> ThreatrayClient:
    if not ctx.request_context or not ctx.request_context.lifespan_context:
        raise RuntimeError("MCP server lifespan context not available")
    client: ThreatrayClient = ctx.request_context.lifespan_context["client"]
    return client
