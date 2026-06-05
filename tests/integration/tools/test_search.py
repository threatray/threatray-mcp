"""Integration tool tests — full path via fastmcp.Client + respx-mocked upstream."""

import unittest

import httpx
import respx
from fastmcp import Client

from threatray_mcp.server import create_server

API_BASE = "https://api.threatray.test"
SHA256 = "a" * 64


class TestSearchTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_search_returns_markdown_summary(self):
        respx.get(f"{API_BASE}/v1/search").mock(
            return_value=httpx.Response(
                200,
                json={
                    "analyses": [
                        {
                            "id": "00000000-0000-0000-0000-000000000001",
                            "sample": {"hash_sha256": SHA256, "first_seen": "2024-01-01T00:00:00"},
                            "verdict": "malicious",
                            "threats": ["Emotet"],
                        }
                    ],
                    "aggregations": {"threats": [{"key": "Emotet", "count": 1}]},
                },
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool("threatray_search", {"params": {"query": "signature:Emotet"}})
        text = result.content[0].text
        self.assertIn("1 analyses found", text)
        self.assertIn("Emotet", text)

    @respx.mock
    async def test_search_spills_when_aggregation_bucket_overflows(self):
        # 3 analyses (well under the 50 inline cap) but a 100-rule YARA
        # bucket means the inline summary would silently lose the long tail.
        # The tool should spill the uncapped markdown to disk and append a
        # `Full markdown saved to: ...` pointer.
        respx.get(f"{API_BASE}/v1/search").mock(
            return_value=httpx.Response(
                200,
                json={
                    "analyses": [
                        {
                            "id": f"00000000-0000-0000-0000-00000000000{i}",
                            "sample": {"hash_sha256": "a" * 64, "first_seen": "2024-01-01"},
                            "verdict": "malicious",
                            "threats": ["Emotet"],
                        }
                        for i in range(1, 4)
                    ],
                    "aggregations": {
                        "yara": [{"key": f"rule_{i:03d}", "count": 1} for i in range(100)],
                    },
                },
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_search", {"params": {"query": "signature:Emotet"}}
            )
        text = result.content[0].text
        # Inline summary: 25 rules + `... and 75 more` footer.
        self.assertIn("rule_000", text)
        self.assertIn("rule_024", text)
        self.assertNotIn("rule_025", text)
        self.assertIn("… and 75 more", text)
        # Spill pointer appended.
        self.assertIn("Full markdown", text)
        self.assertIn(".md", text)


class TestRetrohuntSampleTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_retrohunt_returns_similar_samples(self):
        respx.get(f"{API_BASE}/v1/search").mock(
            return_value=httpx.Response(
                200,
                json={
                    "analyses": [
                        {
                            "id": "00000000-0000-0000-0000-000000000002",
                            "sample": {"hash_sha256": "b" * 64, "first_seen": "2024-02-01"},
                            "verdict": "malicious",
                            "threats": ["CobaltStrike"],
                        }
                    ]
                },
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_retrohunt_sample", {"params": {"sample_hash": SHA256}}
            )
        text = result.content[0].text
        self.assertIn("Similar Samples", text)
        self.assertIn("1 found", text)
