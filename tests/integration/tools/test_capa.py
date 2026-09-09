"""Integration tool tests — full path via fastmcp.Client + respx-mocked upstream."""

import json
import unittest

import httpx
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from threatray_mcp.server import create_server

API_BASE = "https://api.threatray.test"
SHA256 = "a" * 64


class TestCapaStaticTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_capa_returns_existing_results(self):
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(
            return_value=httpx.Response(
                200,
                json={"capabilities": {"rules": {"persistence": {"meta": {"name": "persist via registry"}}}}},
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_get_capa",
                {"params": {"file_hash": SHA256, "trigger_if_missing": False}},
            )
        text = result.content[0].text
        self.assertIn("CAPA Capability Analysis", text)


class TestCapaJobTool(unittest.IsolatedAsyncioTestCase):
    JOB_ID = "00000000-0000-0000-0000-0000000000aa"

    @respx.mock
    async def test_get_capa_job_renders_status(self):
        respx.get(f"{API_BASE}/v1/capa-analysis/jobs/{self.JOB_ID}").mock(
            return_value=httpx.Response(
                200, json={"job_id": self.JOB_ID, "file_hash": SHA256, "job_status": "PROCESSING"}
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool("threatray_get_capa_job", {"params": {"job_id": self.JOB_ID}})
        text = result.content[0].text
        self.assertIn("CAPA Analysis Job", text)
        self.assertIn("PROCESSING", text)

    @respx.mock
    async def test_get_capa_job_json_returns_raw_payload(self):
        respx.get(f"{API_BASE}/v1/capa-analysis/jobs/{self.JOB_ID}").mock(
            return_value=httpx.Response(
                200, json={"job_id": self.JOB_ID, "file_hash": SHA256, "job_status": "DONE"}
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_get_capa_job", {"params": {"job_id": self.JOB_ID, "response_format": "json"}}
            )
        self.assertIn('"job_status"', result.content[0].text)

    @respx.mock
    async def test_unknown_job_surfaces_as_a_tool_error(self):
        """A 404 must reach the caller as an error, not a success-shaped string:
        swallowing it would leave an agent treating 'no such job' as a status."""
        respx.get(f"{API_BASE}/v1/capa-analysis/jobs/{self.JOB_ID}").mock(return_value=httpx.Response(404))
        mcp = create_server()
        async with Client(mcp) as client:
            with self.assertRaises(ToolError) as ctx:
                await client.call_tool("threatray_get_capa_job", {"params": {"job_id": self.JOB_ID}})
        self.assertIn(self.JOB_ID, str(ctx.exception))

    @respx.mock
    async def test_trigger_only_ack_names_the_job_id_and_poll_tool(self):
        """The markdown ack replaced a raw-JSON dump; it must carry the id the
        agent needs and name the tool that polls it."""
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(return_value=httpx.Response(404))
        respx.post(f"{API_BASE}/v1/capa-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": self.JOB_ID, "file_hash": SHA256, "job_status": "QUEUED"})
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_get_capa", {"params": {"file_hash": SHA256, "trigger_only": True}}
            )
        text = result.content[0].text
        self.assertIn(self.JOB_ID, text)
        self.assertIn("threatray_get_capa_job", text)

    @respx.mock
    async def test_trigger_only_json_ack_is_unchanged(self):
        """response_format=json must stay byte-compatible for callers that parse it."""
        respx.get(f"{API_BASE}/v1/capa-analysis/results/latest").mock(return_value=httpx.Response(404))
        respx.post(f"{API_BASE}/v1/capa-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": self.JOB_ID, "file_hash": SHA256, "job_status": "QUEUED"})
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_get_capa",
                {"params": {"file_hash": SHA256, "trigger_only": True, "response_format": "json"}},
            )
        # Byte-for-byte, not just field-wise: reordered or added fields would
        # slip past a per-field check while still breaking a caller that parses
        # this output.
        expected = json.dumps(
            {"job": {"job_id": self.JOB_ID, "file_hash": SHA256, "job_status": "QUEUED"}, "pending": True},
            indent=2,
        )
        self.assertEqual(result.content[0].text, expected)
