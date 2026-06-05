"""Integration tool tests — full path via fastmcp.Client + respx-mocked upstream."""

import unittest

import httpx
import respx
from fastmcp import Client

from threatray_mcp.server import create_server

API_BASE = "https://api.threatray.test"
SHA256 = "a" * 64


class TestGetFileMetadataTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_metadata_passes_include_strings_false_and_renders_pe(self):
        route = respx.get(f"{API_BASE}/v1/files/{SHA256}/metadata").mock(
            return_value=httpx.Response(
                200,
                json={
                    "hash_sha256": SHA256,
                    "magic": "PE32+ executable",
                    "size": 1024,
                    "sections": [
                        {"Name": ".text", "VirtualAddress": 0x1000, "VirtualSize": 0x800, "SizeOfRawData": 0x1000},
                    ],
                },
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_get_file_metadata", {"params": {"file_hash": SHA256}}
            )
        text = result.content[0].text
        self.assertIn("PE32+", text)
        self.assertIn(".text", text)
        # No strings rendering on this tool.
        self.assertNotIn("### Strings", text)
        self.assertIn("include_strings=false", str(route.calls[0].request.url))


class TestGetStringsTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_markdown_spills_full_list_when_probe_trips(self):
        # First call: probe with limit=201 hits the cap → tool refetches
        # unbounded → spill triggers. Both upstream calls return the same
        # 500-string list for this test.
        route = respx.get(f"{API_BASE}/v1/files/{SHA256}/strings").mock(
            return_value=httpx.Response(200, json={"strings": [f"s_{i:04d}" for i in range(500)]})
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_get_strings", {"params": {"file_hash": SHA256}}
            )
        text = result.content[0].text
        # Inline summary capped at 200 entries.
        self.assertIn("more than 200", text)
        self.assertIn("s_0000", text)
        self.assertIn("s_0199", text)
        self.assertNotIn("s_0200", text)
        # Spill pointer appended; agent can Read the cache file to see s_0200+.
        self.assertIn("Full markdown", text)
        self.assertIn(".md", text)
        # Two upstream calls: the limit=201 probe, then an unbounded refetch.
        self.assertEqual(len(route.calls), 2)
        self.assertIn("limit=201", str(route.calls[0].request.url))
        self.assertNotIn("limit=", str(route.calls[1].request.url))

    @respx.mock
    async def test_markdown_renders_full_list_when_short(self):
        respx.get(f"{API_BASE}/v1/files/{SHA256}/strings").mock(
            return_value=httpx.Response(200, json={"strings": ["evil.com", "CreateFileW"]})
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_get_strings", {"params": {"file_hash": SHA256}}
            )
        text = result.content[0].text
        self.assertIn("Strings (2)", text)
        self.assertIn("evil.com", text)
        self.assertIn("CreateFileW", text)
        self.assertNotIn("more than", text)

    @respx.mock
    async def test_json_omits_limit_and_returns_full_payload(self):
        route = respx.get(f"{API_BASE}/v1/files/{SHA256}/strings").mock(
            return_value=httpx.Response(200, json={"strings": ["s1", "s2", "s3"]})
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_get_strings",
                {"params": {"file_hash": SHA256, "response_format": "json"}},
            )
        text = result.content[0].text
        self.assertIn("s1", text)
        self.assertIn("s2", text)
        self.assertIn("s3", text)
        # JSON path doesn't ask for a server-side cap.
        self.assertNotIn("limit", str(route.calls[0].request.url))
