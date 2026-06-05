"""SearchClient tests — covers /v1/search (free-form + retrohunt variant)."""

import unittest

import httpx
import respx

from threatray_mcp.client import SearchClient
from threatray_mcp.client._http import HttpClient
from threatray_mcp.models import SearchScope

API_BASE = "https://api.threatray.test"


class TestSearchClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_client = httpx.AsyncClient()
        self.http = HttpClient(http_client=self.async_client)
        self.client = SearchClient(self.http)

    async def asyncTearDown(self):
        await self.async_client.aclose()

    @respx.mock
    async def test_run_passes_query_max_results_scope(self):
        route = respx.get(f"{API_BASE}/v1/search").mock(
            return_value=httpx.Response(200, json={"analyses": []})
        )
        await self.client.run("signature:Emotet", max_results=25, scope=SearchScope.PRIVATE)
        params = route.calls[0].request.url.params
        self.assertEqual(params["query"], "signature:Emotet")
        self.assertEqual(params["max_results"], "25")
        self.assertEqual(params["scope"], "private")
        # date is unset → not included
        self.assertNotIn("date", params)

    @respx.mock
    async def test_run_includes_date_when_set(self):
        route = respx.get(f"{API_BASE}/v1/search").mock(
            return_value=httpx.Response(200, json={"analyses": []})
        )
        await self.client.run("verdict:malicious", date="30d")
        self.assertEqual(route.calls[0].request.url.params["date"], "30d")

    @respx.mock
    async def test_retrohunt_sample_wraps_hash_in_query(self):
        sha = "a" * 64
        route = respx.get(f"{API_BASE}/v1/search").mock(
            return_value=httpx.Response(200, json={"analyses": []})
        )
        await self.client.retrohunt_sample(sha, max_results=50, scope=SearchScope.BOTH)
        params = route.calls[0].request.url.params
        self.assertEqual(params["query"], f"retrohunt: {sha}")
        self.assertEqual(params["scope"], "both")
