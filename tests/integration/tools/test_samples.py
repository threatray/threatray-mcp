"""Integration tool tests — full path via fastmcp.Client + respx-mocked upstream."""

import unittest

import httpx
import respx
from fastmcp import Client

from threatray_mcp.server import create_server

API_BASE = "https://api.threatray.test"
SHA256 = "a" * 64


class TestGetSampleTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_get_sample_returns_metadata(self):
        respx.get(f"{API_BASE}/v1/samples/{SHA256}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "sample": {
                        "hash_sha256": SHA256,
                        "hash_sha1": "b" * 40,
                        "hash_md5": "c" * 32,
                        "file_name": "evil.exe",
                        "file_type": "PE",
                        "file_size": 12345,
                        "first_seen": "2024-01-01",
                        "verdict": "malicious",
                        "threats": ["Emotet"],
                    },
                    "analyses": [],
                },
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool("threatray_get_sample", {"params": {"sample_hash": SHA256}})
        text = result.content[0].text
        self.assertIn("evil.exe", text)
        self.assertIn("malicious", text)
