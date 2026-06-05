"""SubmissionsClient tests — focus on the multipart submit family + feature gating."""

import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile

import httpx
import respx

from threatray_mcp.client import SubmissionsClient
from threatray_mcp.client._http import HttpClient
from threatray_mcp.errors import ThreatrayNotFound

API_BASE = "https://api.threatray.test"
class TestSubmissionsClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_client = httpx.AsyncClient()
        self.http = HttpClient(http_client=self.async_client)
        self.client = SubmissionsClient(self.http)

    async def asyncTearDown(self):
        await self.async_client.aclose()

    def _tmp_file(self, content: bytes = b"MZ\x90\x00", suffix: str = ".bin") -> str:
        f = NamedTemporaryFile(delete=False, suffix=suffix)
        f.write(content)
        f.close()
        self.addCleanup(lambda: Path(f.name).unlink(missing_ok=True))
        return f.name

    @respx.mock
    async def test_submit_sample_posts_multipart_and_returns_submission(self):
        route = respx.post(f"{API_BASE}/v1/submissions/samples").mock(
            return_value=httpx.Response(
                201,
                json={"submissions": [{"task_id": "abc", "status": "pending"}], "error": None},
            )
        )
        result = await self.client.submit_sample(self._tmp_file(), label="test")
        self.assertEqual(result["submissions"][0]["task_id"], "abc")
        self.assertEqual(route.call_count, 1)

    @respx.mock
    async def test_submit_url_no_file(self):
        respx.post(f"{API_BASE}/v1/submissions/urls").mock(
            return_value=httpx.Response(
                201,
                json={"submissions": [{"task_id": "u1", "status": "pending"}], "error": None},
            )
        )
        result = await self.client.submit_url("https://evil.example.com/payload", label="phish")
        self.assertEqual(result["submissions"][0]["task_id"], "u1")

    @respx.mock
    async def test_submit_minidump(self):
        respx.post(f"{API_BASE}/v1/submissions/minidump").mock(
            return_value=httpx.Response(201, json={"submissions": [{"task_id": "m1", "status": "pending"}]})
        )
        result = await self.client.submit_minidump(self._tmp_file(suffix=".dmp"))
        self.assertEqual(result["submissions"][0]["task_id"], "m1")

    @respx.mock
    async def test_submit_404_propagates_as_not_found(self):
        """A 404 from a submit route propagates as the generic ThreatrayNotFound. Submit
        endpoints are not feature-gated — `enableDeletionProtection` only gates the
        DELETE side."""
        respx.post(f"{API_BASE}/v1/submissions/samples").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayNotFound):
            await self.client.submit_sample(self._tmp_file())

    async def test_submit_sample_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            await self.client.submit_sample("/tmp/definitely_does_not_exist_12345.bin")

    @respx.mock
    async def test_get_task_by_id(self):
        respx.get(f"{API_BASE}/v1/tasks/42").mock(
            return_value=httpx.Response(200, json={"task_id": 42, "status": "done"})
        )
        result = await self.client.get_task(42)
        self.assertEqual(result["task_id"], 42)

    @respx.mock
    async def test_get_task_by_analysis(self):
        aid = "00000000-0000-0000-0000-000000000001"
        respx.get(f"{API_BASE}/v1/tasks/by-analysis/{aid}").mock(
            return_value=httpx.Response(200, json={"task_id": 99, "status": "done"})
        )
        result = await self.client.get_task_by_analysis(aid)
        self.assertEqual(result["task_id"], 99)

    @respx.mock
    async def test_list_tasks_passes_filters(self):
        sha = "a" * 64
        route = respx.get(f"{API_BASE}/v1/tasks").mock(
            return_value=httpx.Response(200, json={"tasks": []})
        )
        await self.client.list_tasks(file_hash=sha, limit=50)
        self.assertEqual(route.call_count, 1)
        self.assertIn("file_hash", route.calls[0].request.url.params)
        self.assertEqual(route.calls[0].request.url.params["file_hash"], sha)
        self.assertEqual(route.calls[0].request.url.params["limit"], "50")

    @respx.mock
    async def test_list_tasks_omits_unset_filters(self):
        route = respx.get(f"{API_BASE}/v1/tasks").mock(
            return_value=httpx.Response(200, json={"tasks": []})
        )
        await self.client.list_tasks(limit=10)
        self.assertNotIn("file_hash", route.calls[0].request.url.params)
        self.assertNotIn("submission_id", route.calls[0].request.url.params)

    @respx.mock
    async def test_list_tasks_passes_through_backend_window(self):
        """The client forwards the backend payload as-is. Any safety cap on
        the rendered view lives in `format_tasks_list` so JSON callers
        receive the unmodified response."""
        respx.get(f"{API_BASE}/v1/tasks").mock(
            return_value=httpx.Response(
                200, json={"tasks": [{"task_id": 1}, {"task_id": 2}]}
            )
        )
        result = await self.client.list_tasks(limit=10)
        self.assertEqual(len(result["tasks"]), 2)

    @respx.mock
    async def test_list_submissions_passes_through_response(self):
        # /v1/submissions has no server-side offset paging, so the client
        # returns the upstream payload verbatim — no synthetic pagination block.
        route = respx.get(f"{API_BASE}/v1/submissions").mock(
            return_value=httpx.Response(200, json={"submissions": [{"task_id": 1}, {"task_id": 2}]})
        )
        result = await self.client.list_submissions(limit=10)
        self.assertEqual(len(result["submissions"]), 2)
        self.assertNotIn("pagination", result)
        # offset must not be forwarded — the endpoint doesn't accept it.
        self.assertNotIn("offset", route.calls.last.request.url.params)

    @respx.mock
    async def test_submit_endpoint_scan_archive(self):
        respx.post(f"{API_BASE}/v1/submissions/endpoint-scan-archive").mock(
            return_value=httpx.Response(201, json={"submissions": [{"task_id": "ea1"}]})
        )
        result = await self.client.submit_endpoint_scan_archive(self._tmp_file(suffix=".zip"))
        self.assertEqual(result["submissions"][0]["task_id"], "ea1")

    @respx.mock
    async def test_submit_mans_file(self):
        respx.post(f"{API_BASE}/v1/submissions/mans-file").mock(
            return_value=httpx.Response(201, json={"submissions": [{"task_id": "mf1"}]})
        )
        result = await self.client.submit_mans_file(self._tmp_file(suffix=".mans"))
        self.assertEqual(result["submissions"][0]["task_id"], "mf1")
