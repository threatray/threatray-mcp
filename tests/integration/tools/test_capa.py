"""Integration tool tests — full path via fastmcp.Client + respx-mocked upstream."""

import unittest

import httpx
import respx
from fastmcp import Client

from threatray_mcp.server import create_server

API_BASE = "https://api.threatray.test"
SHA256 = "a" * 64


class TestCapaStaticTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_capa_returns_existing_results(self):
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(
            return_value=httpx.Response(
                200,
                json={"capabilities": {"rules": {"persistence": {"meta": {"name": "persist via registry"}}}}},
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_get_capa",
                {"params": {"file_hash": SHA256, "trigger_if_missing": False}},
            )
        text = result.content[0].text
        self.assertIn("CAPA Capability Analysis", text)
