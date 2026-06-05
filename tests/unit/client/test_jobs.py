"""JobPoller tests — covers terminal-status disambiguation, timeout, and progress."""

import unittest

import httpx
import respx

from threatray_mcp.client._http import HttpClient
from threatray_mcp.client._jobs import JobPoller
from threatray_mcp.errors import ThreatrayJobFailed, ThreatrayJobTimeout

API_BASE = "https://api.threatray.test"
PREFIX = "/v1/capa-analysis"

class TestJobPoller(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.async_client = httpx.AsyncClient()
        self.http = HttpClient(http_client=self.async_client)
        self.poller = JobPoller(self.http, PREFIX, "CAPA", poll_interval=0, timeout=10)

    async def asyncTearDown(self):
        await self.async_client.aclose()

    @respx.mock
    async def test_done_returns_job(self):
        respx.get(f"{API_BASE}{PREFIX}/jobs/42").mock(
            return_value=httpx.Response(200, json={"job_id": 42, "job_status": "DONE"})
        )
        job = await self.poller.poll(42)
        self.assertEqual(job["job_status"], "DONE")

    @respx.mock
    async def test_failed_raises_job_failed(self):
        respx.get(f"{API_BASE}{PREFIX}/jobs/42").mock(
            return_value=httpx.Response(200, json={"job_id": 42, "job_status": "FAILED"})
        )
        with self.assertRaises(ThreatrayJobFailed):
            await self.poller.poll(42)

    @respx.mock
    async def test_progress_then_done(self):
        route = respx.get(f"{API_BASE}{PREFIX}/jobs/42").mock(
            side_effect=[
                httpx.Response(200, json={"job_id": 42, "job_status": "PROCESSING"}),
                httpx.Response(200, json={"job_id": 42, "job_status": "DONE"}),
            ]
        )
        progress_calls: list[tuple[float, str]] = []

        async def progress_callback(progress: float, message: str) -> None:
            progress_calls.append((progress, message))

        job = await self.poller.poll(42, progress_callback)
        self.assertEqual(job["job_status"], "DONE")
        self.assertEqual(route.call_count, 2)
        self.assertGreater(len(progress_calls), 0)

    @respx.mock
    async def test_extra_terminal_failure_status(self):
        """AI analysis treats UNSUPPORTED/SKIPPED as terminal failures."""
        poller = JobPoller(
            self.http,
            "/v1/ai-analysis",
            "AI analysis",
            poll_interval=0,
            timeout=10,
            extra_terminal_failures=("UNSUPPORTED", "SKIPPED"),
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/abc").mock(
            return_value=httpx.Response(200, json={"job_id": "abc", "job_status": "UNSUPPORTED"})
        )
        with self.assertRaises(ThreatrayJobFailed):
            await poller.poll("abc")

    @respx.mock
    async def test_timeout(self):
        """When the timeout is zero, the very first iteration must raise ThreatrayJobTimeout."""
        respx.get(f"{API_BASE}{PREFIX}/jobs/42").mock(
            return_value=httpx.Response(200, json={"job_id": 42, "job_status": "PROCESSING"})
        )
        poller = JobPoller(self.http, PREFIX, "CAPA", poll_interval=0, timeout=-1)
        with self.assertRaises(ThreatrayJobTimeout):
            await poller.poll(42)
