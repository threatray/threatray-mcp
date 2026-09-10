"""CapaClient tests — covers trigger-if-missing and the not-found vs trigger paths."""

import unittest

import httpx
import respx

from threatray_mcp.client import CapaClient
from threatray_mcp.client._http import HttpClient
from threatray_mcp.errors import ThreatrayNotFound

API_BASE = "https://api.threatray.test"
SHA = "a" * 64
JOB_ID = "00000000-0000-0000-0000-0000000000aa"

class TestCapaClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_client = httpx.AsyncClient()
        self.http = HttpClient(http_client=self.async_client)
        self.client = CapaClient(self.http, poll_interval=0, timeout=10)

    async def asyncTearDown(self):
        await self.async_client.aclose()

    @respx.mock
    async def test_get_existing_results_returns_payload(self):
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(
            return_value=httpx.Response(200, json={"capabilities": {"rules": {}}})
        )
        result = await self.client.get(SHA, trigger_if_missing=False)
        self.assertEqual(result, {"capabilities": {"rules": {}}})

    @respx.mock
    async def test_get_404_without_trigger_raises_not_found(self):
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayNotFound):
            await self.client.get(SHA, trigger_if_missing=False)

    @respx.mock
    async def test_get_404_with_trigger_creates_job_and_fetches(self):
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(
            side_effect=[
                httpx.Response(404),
                httpx.Response(200, json={"capabilities": {"rules": {"r1": {}}}}),
            ]
        )
        respx.post(f"{API_BASE}/v1/capa-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": 99, "job_status": "QUEUED"})
        )
        respx.get(f"{API_BASE}/v1/capa-analysis/jobs/99").mock(
            return_value=httpx.Response(200, json={"job_id": 99, "job_status": "DONE"})
        )
        result = await self.client.get(SHA, trigger_if_missing=True)
        self.assertIn("capabilities", result)

    @respx.mock
    async def test_trigger_only_returns_job_without_polling(self):
        """trigger_only=True: enqueue the job, return immediately, no /jobs/{id} call."""
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(return_value=httpx.Response(404))
        post_route = respx.post(f"{API_BASE}/v1/capa-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": 99, "job_status": "QUEUED"})
        )
        result = await self.client.get(SHA, trigger_if_missing=True, trigger_only=True)
        self.assertEqual(result["pending"], True)
        self.assertEqual(result["job"]["job_id"], 99)
        self.assertEqual(post_route.call_count, 1)

    @respx.mock
    async def test_get_job_returns_status(self):
        """get_job delegates to the poller's job URL and returns the raw payload."""
        route = respx.get(f"{API_BASE}/v1/capa-analysis/jobs/{JOB_ID}").mock(
            return_value=httpx.Response(
                200, json={"job_id": JOB_ID, "file_hash": SHA, "job_status": "PROCESSING"}
            )
        )
        result = await self.client.get_job(JOB_ID)
        self.assertEqual(result["job_status"], "PROCESSING")
        self.assertEqual(route.call_count, 1)

    @respx.mock
    async def test_get_job_404_names_the_id_without_claiming_a_cause(self):
        """A job-route 404 is ambiguous (unknown id vs route absent for this realm),
        so the message names the id but must not assert a cause."""
        respx.get(f"{API_BASE}/v1/capa-analysis/jobs/{JOB_ID}").mock(return_value=httpx.Response(404))
        with self.assertRaises(ThreatrayNotFound) as ctx:
            await self.client.get_job(JOB_ID)
        self.assertIn(JOB_ID, str(ctx.exception))
        self.assertNotIn("Resource not found", str(ctx.exception))
