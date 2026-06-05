"""SamplesClient tests."""

import unittest

import httpx
import respx

from threatray_mcp.client import SamplesClient
from threatray_mcp.client._http import HttpClient

API_BASE = "https://api.threatray.test"
SHA256 = "a" * 64

class TestSamplesClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_client = httpx.AsyncClient()
        self.http = HttpClient(http_client=self.async_client)
        self.client = SamplesClient(self.http)

    async def asyncTearDown(self):
        await self.async_client.aclose()

    @respx.mock
    async def test_get(self):
        respx.get(f"{API_BASE}/v1/samples/{SHA256}").mock(
            return_value=httpx.Response(200, json={"sample": {"hash_sha256": SHA256}})
        )
        result = await self.client.get(SHA256)
        self.assertEqual(result["sample"]["hash_sha256"], SHA256)
