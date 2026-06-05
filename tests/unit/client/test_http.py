"""Verifies HttpClient maps httpx errors at the boundary into ThreatrayError subclasses."""

import unittest

import httpx
import respx

from threatray_mcp.client._http import HttpClient
from threatray_mcp.errors import (
    ThreatrayAuthError,
    ThreatrayBadRequest,
    ThreatrayConnectionError,
    ThreatrayForbiddenError,
    ThreatrayNotFound,
    ThreatrayRateLimitError,
    ThreatrayServerError,
    ThreatrayTimeoutError,
)

API_BASE = "https://api.threatray.test"


class TestHttpClientErrorMapping(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_client = httpx.AsyncClient()
        self.http = HttpClient(http_client=self.async_client)

    async def asyncTearDown(self):
        await self.async_client.aclose()

    @respx.mock
    async def test_400_maps_to_bad_request(self):
        respx.get(f"{API_BASE}/v1/x").mock(return_value=httpx.Response(400, text="missing field"))
        with self.assertRaises(ThreatrayBadRequest) as ctx:
            await self.http.get("/v1/x")
        self.assertEqual(ctx.exception.status_code, 400)

    @respx.mock
    async def test_401_maps_to_auth(self):
        respx.get(f"{API_BASE}/v1/x").mock(return_value=httpx.Response(401, text="nope"))
        with self.assertRaises(ThreatrayAuthError) as ctx:
            await self.http.get("/v1/x")
        self.assertEqual(ctx.exception.status_code, 401)

    @respx.mock
    async def test_403_maps_to_forbidden(self):
        respx.get(f"{API_BASE}/v1/x").mock(return_value=httpx.Response(403))
        with self.assertRaises(ThreatrayForbiddenError):
            await self.http.get("/v1/x")

    @respx.mock
    async def test_404_maps_to_not_found(self):
        respx.get(f"{API_BASE}/v1/x").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayNotFound):
            await self.http.get("/v1/x")

    @respx.mock
    async def test_429_maps_to_rate_limit(self):
        respx.get(f"{API_BASE}/v1/x").mock(return_value=httpx.Response(429))
        with self.assertRaises(ThreatrayRateLimitError):
            await self.http.get("/v1/x")

    @respx.mock
    async def test_500_maps_to_server_error(self):
        respx.get(f"{API_BASE}/v1/x").mock(return_value=httpx.Response(500, text="boom"))
        with self.assertRaises(ThreatrayServerError):
            await self.http.get("/v1/x")

    @respx.mock
    async def test_503_maps_to_server_error(self):
        respx.get(f"{API_BASE}/v1/x").mock(return_value=httpx.Response(503))
        with self.assertRaises(ThreatrayServerError):
            await self.http.get("/v1/x")

    @respx.mock
    async def test_timeout_maps_to_timeout_error(self):
        respx.get(f"{API_BASE}/v1/x").mock(side_effect=httpx.TimeoutException("slow"))
        with self.assertRaises(ThreatrayTimeoutError):
            await self.http.get("/v1/x")

    @respx.mock
    async def test_connect_error_maps_to_connection_error(self):
        respx.get(f"{API_BASE}/v1/x").mock(side_effect=httpx.ConnectError("no route"))
        with self.assertRaises(ThreatrayConnectionError):
            await self.http.get("/v1/x")

    @respx.mock
    async def test_200_returns_json(self):
        respx.get(f"{API_BASE}/v1/x").mock(return_value=httpx.Response(200, json={"ok": True}))
        result = await self.http.get("/v1/x")
        self.assertEqual(result, {"ok": True})
