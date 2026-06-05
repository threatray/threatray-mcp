"""Integration tool tests for the submissions section — full path via
fastmcp.Client + respx-mocked upstream. Covers the listing + lookup tools and
one URL submission. The file-upload submits (submit_sample, submit_minidump,
submit_mans_file, submit_endpoint_scan_archive) need a real path on disk;
those are covered end-to-end in the e2e suite where realm fixtures live.
"""

import os
import tempfile
import unittest

import httpx
import respx
from fastmcp import Client

from tests.dummies import DUMMY_SAMPLE_ANALYSIS_ID, DUMMY_SHA256, DUMMY_SUBMISSION_ID
from threatray_mcp.server import create_server

API_BASE = "https://api.threatray.test"


class TestListSubmissionsTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_list_submissions_renders_status(self):
        respx.get(f"{API_BASE}/v1/submissions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "submissions": [
                        {
                            "id": DUMMY_SUBMISSION_ID,
                            "status": "done",
                            "label": "test",
                            "submission_time": 1777557617,
                        }
                    ]
                },
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool("threatray_list_submissions", {"params": {}})
        text = result.content[0].text
        self.assertIn("done", text)


class TestGetTaskTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_get_task_returns_payload(self):
        respx.get(f"{API_BASE}/v1/tasks/42").mock(
            return_value=httpx.Response(
                200, json={"task_id": 42, "status": "done", "analysis_id": DUMMY_SAMPLE_ANALYSIS_ID}
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool("threatray_get_task", {"params": {"task_id": 42}})
        text = result.content[0].text
        self.assertIn("42", text)


class TestGetTaskByAnalysisTool(unittest.IsolatedAsyncioTestCase):
    """`/v1/tasks/by-analysis/{id}` returns a *list* of task objects — one
    analysis can produce multiple tasks (e.g. static + dynamic from one
    submission). The tool renders the first and notes siblings."""

    @respx.mock
    async def test_task_by_analysis_unwraps_first_item(self):
        respx.get(f"{API_BASE}/v1/tasks/by-analysis/{DUMMY_SAMPLE_ANALYSIS_ID}").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "task_id": 43,
                        "analysis_id": DUMMY_SAMPLE_ANALYSIS_ID,
                        "status": "done",
                    },
                    {
                        "task_id": 44,
                        "analysis_id": DUMMY_SAMPLE_ANALYSIS_ID,
                        "status": "done",
                    },
                ],
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_get_task_by_analysis",
                {"params": {"analysis_id": DUMMY_SAMPLE_ANALYSIS_ID}},
            )
        text = result.content[0].text
        self.assertIn("43", text)
        self.assertIn("Analysis produced 2 tasks", text)


class TestListTasksTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_list_tasks_forwards_hash_filter(self):
        route = respx.get(f"{API_BASE}/v1/tasks").mock(
            return_value=httpx.Response(200, json={"tasks": []})
        )
        mcp = create_server()
        async with Client(mcp) as client:
            await client.call_tool(
                "threatray_list_tasks", {"params": {"file_hash": DUMMY_SHA256}}
            )
        self.assertEqual(
            route.calls[0].request.url.params["file_hash"], DUMMY_SHA256
        )


class TestSubmitUrlTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_submit_url_posts_multipart(self):
        respx.post(f"{API_BASE}/v1/submissions/urls").mock(
            return_value=httpx.Response(
                200, json={"submissions": [{"submission_id": DUMMY_SUBMISSION_ID, "task_id": 99}]}
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_submit_url",
                {"params": {"url": "https://example.com/sample.exe", "response_format": "json"}},
            )
        text = result.content[0].text
        self.assertIn(DUMMY_SUBMISSION_ID, text)


class TestSubmitSampleTool(unittest.IsolatedAsyncioTestCase):
    """Cover the file-upload path by writing a throwaway tempfile and
    asserting the multipart POST lands on /v1/submissions/samples. Doesn't
    validate that the file payload survives the encoder — that's covered by
    the SubmissionsClient unit tests with explicit multipart asserts."""

    @respx.mock
    async def test_submit_sample_uploads_file_and_returns_id(self):
        respx.post(f"{API_BASE}/v1/submissions/samples").mock(
            return_value=httpx.Response(
                200, json={"submissions": [{"submission_id": DUMMY_SUBMISSION_ID, "task_id": 7}]}
            )
        )
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            f.write(b"MZ\x00\x00")
            tmp_path = f.name
        try:
            mcp = create_server()
            async with Client(mcp) as client:
                result = await client.call_tool(
                    "threatray_submit_sample",
                    {
                        "params": {
                            "file_path": tmp_path,
                            "analysis_mode": "static",
                            "response_format": "json",
                        }
                    },
                )
            text = result.content[0].text
            self.assertIn(DUMMY_SUBMISSION_ID, text)
        finally:
            os.unlink(tmp_path)
