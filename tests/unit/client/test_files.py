"""FilesClient tests — covers /v1/files/{hash}/{metadata,strings,data}."""

import unittest

import httpx
import respx

from threatray_mcp.client import FilesClient
from threatray_mcp.client._http import HttpClient
from threatray_mcp.errors import ThreatrayNotFound

API_BASE = "https://api.threatray.test"
SHA256 = "a" * 64


class TestFilesClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_client = httpx.AsyncClient()
        self.http = HttpClient(http_client=self.async_client)
        self.client = FilesClient(self.http)

    async def asyncTearDown(self):
        await self.async_client.aclose()

    @respx.mock
    async def test_get_metadata_passes_include_strings_false(self):
        """The MCP never wants strings on /metadata — that's what
        `threatray_get_strings` exists for. Verify the query param is wired
        through to spare the data-layer the extra full-buffer scan."""
        payload = {
            "file_header": {"machine": "x86_64"},
            "sections": [{"name": ".text", "size": 1024}],
            "imports": [],
            "exports": [],
            "hash_sha256": SHA256,
        }
        route = respx.get(f"{API_BASE}/v1/files/{SHA256}/metadata").mock(
            return_value=httpx.Response(200, json=payload)
        )
        result = await self.client.get_metadata(SHA256)
        self.assertEqual(result, payload)
        self.assertEqual(route.call_count, 1)
        request_url = str(route.calls[0].request.url)
        self.assertIn("include_strings=false", request_url)

    @respx.mock
    async def test_get_metadata_propagates_not_found(self):
        respx.get(f"{API_BASE}/v1/files/{SHA256}/metadata").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayNotFound):
            await self.client.get_metadata(SHA256)

    @respx.mock
    async def test_get_strings_returns_payload(self):
        payload = {"strings": ["evil.com", "CreateFileW", "Mutex42"]}
        route = respx.get(f"{API_BASE}/v1/files/{SHA256}/strings").mock(
            return_value=httpx.Response(200, json=payload)
        )
        result = await self.client.get_strings(SHA256)
        self.assertEqual(result, payload)
        self.assertEqual(route.call_count, 1)
        # No `limit` passed → no `limit` query param.
        self.assertNotIn("limit", str(route.calls[0].request.url))

    @respx.mock
    async def test_get_strings_forwards_limit_query_param(self):
        route = respx.get(f"{API_BASE}/v1/files/{SHA256}/strings").mock(
            return_value=httpx.Response(200, json={"strings": []})
        )
        await self.client.get_strings(SHA256, limit=201)
        self.assertIn("limit=201", str(route.calls[0].request.url))

    @respx.mock
    async def test_get_strings_propagates_not_found(self):
        respx.get(f"{API_BASE}/v1/files/{SHA256}/strings").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayNotFound):
            await self.client.get_strings(SHA256)

    @respx.mock
    async def test_download_returns_bytes_and_uses_zipped_query(self):
        respx.get(url__regex=rf"{API_BASE}/v1/files/{SHA256}/data\?zipped").mock(
            return_value=httpx.Response(200, content=b"PK\x03\x04zipdata")
        )
        data = await self.client.download(SHA256, zipped=True)
        self.assertEqual(data, b"PK\x03\x04zipdata")

    @respx.mock
    async def test_download_without_zipped_flag(self):
        route = respx.get(f"{API_BASE}/v1/files/{SHA256}/data").mock(
            return_value=httpx.Response(200, content=b"raw-bytes")
        )
        data = await self.client.download(SHA256, zipped=False)
        self.assertEqual(data, b"raw-bytes")
        self.assertEqual(route.call_count, 1)
        self.assertNotIn("zipped", str(route.calls[0].request.url))
