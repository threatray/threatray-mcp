"""Integration tool tests — full path via fastmcp.Client + respx-mocked upstream."""

import unittest

import httpx
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from threatray_mcp.server import create_server

API_BASE = "https://api.threatray.test"
SHA256 = "a" * 64


class TestAiAnalysisFeatureUnavailable(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_ai_analysis_404_surfaces_as_tool_error(self):
        """When AI analysis is disabled for the realm, /v1/ai-analysis/results 404s.
        Our section-client translates this to ThreatrayFeatureUnavailable; FastMCP
        wraps it into a ToolError visible to the MCP client (not a string-wrapped
        success that hides the failure)."""
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(404))
        mcp = create_server()
        async with Client(mcp) as client:
            with self.assertRaises(ToolError) as ctx:
                await client.call_tool(
                    "threatray_get_ai_analysis",
                    {"params": {"file_hash": SHA256, "trigger_if_missing": False}},
                )
        self.assertIn("AI analysis is not enabled", str(ctx.exception))
