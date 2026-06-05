"""FunctionsClient tests — list / code-detections / retrohunt / diff."""

import json
import unittest

import httpx
import respx

from threatray_mcp.client import FunctionsClient
from threatray_mcp.client._http import HttpClient
from threatray_mcp.errors import ThreatrayNotFound
from threatray_mcp.models import SearchScope

API_BASE = "https://api.threatray.test"
SHA256 = "a" * 64


class TestFunctionsClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_client = httpx.AsyncClient()
        self.http = HttpClient(http_client=self.async_client)
        self.client = FunctionsClient(self.http)

    async def asyncTearDown(self):
        await self.async_client.aclose()

    @respx.mock
    async def test_list_functions(self):
        respx.get(f"{API_BASE}/v1/functions/{SHA256}").mock(
            return_value=httpx.Response(200, json={"functions": [{"uid": "fn-1"}]})
        )
        result = await self.client.list_functions(SHA256)
        self.assertEqual(result["functions"][0]["uid"], "fn-1")

    @respx.mock
    async def test_list_functions_passes_scoping_filters(self):
        route = respx.get(f"{API_BASE}/v1/functions/{SHA256}").mock(
            return_value=httpx.Response(200, json={"functions": []})
        )
        await self.client.list_functions(SHA256, analysis_id="aid", pid=123, base=0x400000)
        params = route.calls[0].request.url.params
        self.assertEqual(params["analysis_id"], "aid")
        self.assertEqual(params["pid"], "123")
        self.assertEqual(params["base"], str(0x400000))

    @respx.mock
    async def test_get_code_detections(self):
        route = respx.get(f"{API_BASE}/v1/functions/code-detections").mock(
            return_value=httpx.Response(200, json={"functions": []})
        )
        await self.client.get_code_detections(SHA256)
        self.assertEqual(route.calls[0].request.url.params["hash"], SHA256)

    @respx.mock
    async def test_run_retrohunt_single_uid_duplicates_internally(self):
        route = respx.get(f"{API_BASE}/v1/retrohunt/functions").mock(
            return_value=httpx.Response(200, json={"analyses": []})
        )
        await self.client.run_retrohunt(["uid-1"], threshold=0.5, scope=SearchScope.BOTH)
        # The single-uid case duplicates the UID to satisfy a backend constraint.
        uids = route.calls[0].request.url.params.get_list("uids")
        self.assertEqual(uids, ["uid-1", "uid-1"])

    @respx.mock
    async def test_run_retrohunt_threshold_is_passed_through_verbatim(self):
        """The backend accepts a ratio in [0.0, 1.0]; the client must not transform it."""
        route = respx.get(f"{API_BASE}/v1/retrohunt/functions").mock(
            return_value=httpx.Response(200, json={"analyses": []})
        )
        await self.client.run_retrohunt(["uid-1", "uid-2", "uid-3"], threshold=0.8)
        self.assertEqual(route.calls[0].request.url.params["threshold"], "0.8")

    @respx.mock
    async def test_run_retrohunt_default_threshold_is_zero(self):
        """Default 0.0 mirrors the backend's `DEFAULT_FUNCTION_RATIO_THRESHOLD`."""
        route = respx.get(f"{API_BASE}/v1/retrohunt/functions").mock(
            return_value=httpx.Response(200, json={"analyses": []})
        )
        await self.client.run_retrohunt(["uid-1", "uid-2"])
        self.assertEqual(route.calls[0].request.url.params["threshold"], "0.0")

    @respx.mock
    async def test_run_retrohunt_scope_is_enum_value(self):
        route = respx.get(f"{API_BASE}/v1/retrohunt/functions").mock(
            return_value=httpx.Response(200, json={"analyses": []})
        )
        await self.client.run_retrohunt(["uid-1", "uid-2"], scope=SearchScope.PRIVATE)
        self.assertEqual(route.calls[0].request.url.params["scope"], "private")

    @respx.mock
    async def test_diff_404_propagates_as_not_found(self):
        """/v1/functions/diff 404 → ThreatrayNotFound (generic mapping)."""
        respx.post(f"{API_BASE}/v1/functions/diff").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayNotFound):
            await self.client.diff("a" * 64, ["b" * 64])

    @respx.mock
    async def test_diff_200_returns_diff_response(self):
        respx.post(f"{API_BASE}/v1/functions/diff").mock(
            return_value=httpx.Response(200, json={"source_file": {}, "files": [], "functions": []})
        )
        result = await self.client.diff("a" * 64, ["b" * 64])
        self.assertEqual(result, {"source_file": {}, "files": [], "functions": []})

    @respx.mock
    async def test_diff_sends_expected_body(self):
        route = respx.post(f"{API_BASE}/v1/functions/diff").mock(
            return_value=httpx.Response(200, json={"source_file": {}, "files": [], "functions": []})
        )
        await self.client.diff(
            "a" * 64,
            ["b" * 64, "c" * 64],
            with_benign_code=True,
            threshold=0.7,
        )
        body = json.loads(route.calls[0].request.content)
        self.assertEqual(body["source_file"], {"hash": "a" * 64})
        self.assertEqual(body["target_files"], [{"hash": "b" * 64}, {"hash": "c" * 64}])
        self.assertEqual(body["with_benign_code"], True)
        self.assertEqual(body["threshold"], 0.7)
