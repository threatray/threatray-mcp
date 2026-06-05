"""Threatray MCP Server.

Constructs the FastMCP instance, owns the per-session httpx lifespan, and registers
all public tools via `tools.register_all(mcp)`.

Internal packages that extend the public server should call `create_server()` to
obtain a fresh FastMCP, then register their own tool modules on top.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastmcp import FastMCP

from . import tools
from .client import ThreatrayClient
from .config import settings


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Manage the per-session httpx client and the ThreatrayClient facade."""
    missing = [name for name, value in (("THREATRAY_API_KEY", settings.api_key),
                                         ("THREATRAY_API_URL", settings.api_url)) if not value]
    if missing:
        raise ValueError(
            f"{' and '.join(missing)} must be set. Point THREATRAY_API_URL at the API endpoint "
            "of the realm your key belongs to (e.g. `https://api-<realm>.analysis.threatray.com`)."
        )

    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0)) as http_client:
        client = ThreatrayClient(http_client=http_client)
        yield {"client": client}


def create_server() -> FastMCP:
    """Build a FastMCP server with all public tools registered."""
    mcp = FastMCP("threatray_mcp", lifespan=lifespan)
    tools.register_all(mcp)
    return mcp
