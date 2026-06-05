"""Tool registration for the Threatray MCP server.

`register_all(mcp)` registers every public tool. Internal packages that extend the
public server import `create_server` from `threatray_mcp.server`, then add their own
register-style modules on top.
"""

from fastmcp import FastMCP

from . import ai_analysis, analyses, capa, files, functions, samples, search, submissions


def register_all(mcp: FastMCP) -> None:
    search.register(mcp)
    samples.register(mcp)
    submissions.register(mcp)
    analyses.register(mcp)
    files.register(mcp)
    functions.register(mcp)
    capa.register(mcp)
    ai_analysis.register(mcp)
