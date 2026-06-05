"""AnalysesClient tests — covers cursor-paginated /v1/analyses/* listings."""

import unittest

import httpx
import respx

from threatray_mcp.client import AnalysesClient
from threatray_mcp.client._http import HttpClient
from threatray_mcp.models import Verdict

API_BASE = "https://api.threatray.test"
class TestAnalysesClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_client = httpx.AsyncClient()
        self.http = HttpClient(http_client=self.async_client)
        self.client = AnalysesClient(self.http)

    async def asyncTearDown(self):
        await self.async_client.aclose()

    @respx.mock
    async def test_get_analysis_by_id(self):
        aid = "00000000-0000-0000-0000-000000000001"
        respx.get(f"{API_BASE}/v1/analyses/{aid}").mock(
            return_value=httpx.Response(200, json={"analysis": {"id": aid}})
        )
        result = await self.client.get(aid)
        self.assertEqual(result["analysis"]["id"], aid)

    @respx.mock
    async def test_osint_by_hash(self):
        sha = "a" * 64
        respx.get(f"{API_BASE}/v1/osint/{sha}").mock(
            return_value=httpx.Response(200, json={"reports": []})
        )
        result = await self.client.osint(sha)
        self.assertEqual(result, {"reports": []})

    @respx.mock
    async def test_list_samples_passes_filters_and_cursor(self):
        route = respx.get(f"{API_BASE}/v1/analyses/samples").mock(
            return_value=httpx.Response(200, json={"analyses": [], "cursor": "next"})
        )
        await self.client.list_samples(
            verdicts=[Verdict.MALICIOUS, Verdict.SUSPICIOUS],
            from_finished_at="2026-01-01T00:00:00Z",
            limit=100,
            cursor="prev",
        )
        params = route.calls[0].request.url.params
        self.assertEqual(params.get_list("verdicts"), ["malicious", "suspicious"])
        self.assertEqual(params["from_finished_at"], "2026-01-01T00:00:00Z")
        self.assertEqual(params["limit"], "100")
        self.assertEqual(params["cursor"], "prev")

    async def test_list_samples_rejects_invalid_verdict(self):
        """Defence-in-depth: even if a caller bypasses the model layer and pushes
        a raw string into the client, the Verdict() coercion raises so we don't
        forward a bogus param the API would 400 on."""
        with self.assertRaises(ValueError):
            await self.client.list_samples(verdicts=["malicious", "bogus"])

    @respx.mock
    async def test_list_endpoint_scans_passes_filters_and_cursor(self):
        route = respx.get(f"{API_BASE}/v1/analyses/endpoint-scans").mock(
            return_value=httpx.Response(200, json={"analyses": [], "cursor": "next"})
        )
        await self.client.list_endpoint_scans(
            verdicts=[Verdict.MALICIOUS, Verdict.SUSPICIOUS],
            from_finished_at="2026-01-01T00:00:00Z",
            limit=100,
            cursor="prev",
        )
        params = route.calls[0].request.url.params
        self.assertEqual(params.get_list("verdicts"), ["malicious", "suspicious"])
        self.assertEqual(params["from_finished_at"], "2026-01-01T00:00:00Z")
        self.assertEqual(params["limit"], "100")
        self.assertEqual(params["cursor"], "prev")

    async def test_list_endpoint_scans_rejects_invalid_verdict(self):
        """Defence-in-depth: even if a caller bypasses the model layer and pushes
        a raw string into the client, the Verdict() coercion raises so we don't
        forward a bogus param the API would 400 on."""
        with self.assertRaises(ValueError):
            await self.client.list_endpoint_scans(verdicts=["malicious", "bogus"])

    @respx.mock
    async def test_list_endpoint_scans_returns_cursor(self):
        respx.get(f"{API_BASE}/v1/analyses/endpoint-scans").mock(
            return_value=httpx.Response(200, json={"analyses": [{"id": "a1"}], "cursor": "next"})
        )
        result = await self.client.list_endpoint_scans()
        self.assertEqual(result["analyses"][0]["id"], "a1")
        self.assertEqual(result["cursor"], "next")
