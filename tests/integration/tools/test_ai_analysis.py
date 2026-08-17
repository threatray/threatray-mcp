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


class TestAiAnalysisProgress(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_blocking_tool_reports_indeterminate_progress(self):
        result_id = "00000000-0000-0000-0000-000000000001"
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(200, json={"results": []}))
        respx.post(f"{API_BASE}/v1/ai-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "QUEUED"})
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/j1").mock(
            return_value=httpx.Response(
                200,
                json={"job_id": "j1", "job_status": "DONE", "result_id": result_id},
            )
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/results/{result_id}").mock(
            return_value=httpx.Response(
                200,
                json={"id": result_id, "file_hash": SHA256, "assessment": "complete"},
            )
        )
        updates: list[tuple[float, float | None, str | None]] = []

        async def progress_handler(progress: float, total: float | None, message: str | None) -> None:
            updates.append((progress, total, message))

        mcp = create_server()
        async with Client(mcp, progress_handler=progress_handler) as client:
            await client.call_tool(
                "threatray_get_ai_analysis",
                {"params": {"file_hash": SHA256, "trigger_if_missing": True}},
            )

        self.assertTrue(updates)
        self.assertTrue(all(total is None for _, total, _ in updates))
        self.assertTrue(any(message == "AI analysis: Complete" for _, _, message in updates))
