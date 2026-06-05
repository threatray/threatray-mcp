"""Smoke test: every registered MCP tool can be invoked with valid input and a
mocked happy-path upstream response without raising.

Cheap safety net for tool-layer glue bugs (Pydantic ↔ section client ↔ formatter).
Real-API verification lives separately, against a configured Threatray realm.
"""

import re
import unittest
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import httpx
import respx
from fastmcp import Client

from threatray_mcp.server import create_server

API_BASE = "https://api.threatray.test"

SHA256 = "a" * 64
SHA256_B = "b" * 64
SHA1 = "a" * 40
MD5 = "a" * 32
ANALYSIS_ID = "00000000-0000-0000-0000-000000000001"


@dataclass
class ToolSpec:
    name: str
    params: dict[str, Any]
    method: str
    path_regex: str
    response_json: dict[str, Any] | None = None
    response_bytes: bytes | None = None


class TestAllToolsSmoke(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmpfiles: list[Path] = []

    @classmethod
    def tearDownClass(cls):
        for p in cls._tmpfiles:
            p.unlink(missing_ok=True)

    @classmethod
    def _tmpfile(cls, suffix: str = ".bin", content: bytes = b"MZ\x90\x00") -> str:
        f = NamedTemporaryFile(delete=False, suffix=suffix)
        f.write(content)
        f.close()
        cls._tmpfiles.append(Path(f.name))
        return f.name

    def _specs(self) -> list[ToolSpec]:
        sample = self._tmpfile()
        return [
            ToolSpec("threatray_search", {"query": "signature:Emotet", "max_results": 5},
                     "GET", re.escape(f"{API_BASE}/v1/search"),
                     {"analyses": []}),
            ToolSpec("threatray_retrohunt_sample", {"sample_hash": SHA256},
                     "GET", re.escape(f"{API_BASE}/v1/search"),
                     {"analyses": []}),
            ToolSpec("threatray_get_sample", {"sample_hash": SHA256},
                     "GET", re.escape(f"{API_BASE}/v1/samples/{SHA256}"),
                     {"sample": {"hash_sha256": SHA256, "file_name": "x.exe"}}),
            ToolSpec("threatray_list_submissions", {},
                     "GET", re.escape(f"{API_BASE}/v1/submissions"),
                     {"submissions": [], "total": 0}),
            ToolSpec("threatray_get_analysis", {"analysis_id": ANALYSIS_ID},
                     "GET", re.escape(f"{API_BASE}/v1/analyses/{ANALYSIS_ID}"),
                     {"analysis": {"id": ANALYSIS_ID}, "sample": {}, "ioc": {}}),
            ToolSpec("threatray_get_osint", {"hash": SHA256},
                     "GET", re.escape(f"{API_BASE}/v1/osint/{SHA256}"),
                     {"reports": []}),
            ToolSpec("threatray_get_file_metadata", {"file_hash": SHA256},
                     "GET", re.escape(f"{API_BASE}/v1/files/{SHA256}/metadata"),
                     {"file_header": {"machine": "x86_64"}, "sections": []}),
            ToolSpec("threatray_get_strings", {"file_hash": SHA256},
                     "GET", re.escape(f"{API_BASE}/v1/files/{SHA256}/strings"),
                     {"strings": ["evil.com", "CreateFileW"]}),
            ToolSpec("threatray_list_functions", {"file_hash": SHA256},
                     "GET", re.escape(f"{API_BASE}/v1/functions/{SHA256}"),
                     {"functions": []}),
            ToolSpec("threatray_get_code_detections", {"hash_sha256": SHA256},
                     "GET", re.escape(f"{API_BASE}/v1/functions/code-detections"),
                     {"functions": []}),
            ToolSpec("threatray_retrohunt_functions", {"function_uids": ["uid-1"]},
                     "GET", re.escape(f"{API_BASE}/v1/retrohunt/functions"),
                     {"functions": [], "code_regions": [], "samples": [], "analyses": []}),
            ToolSpec("threatray_diff_functions",
                     {"source_hash": SHA256, "target_hashes": [SHA256_B]},
                     "POST", re.escape(f"{API_BASE}/v1/functions/diff"),
                     {"source_file": {}, "files": [], "functions": []}),
            ToolSpec("threatray_get_capa", {"file_hash": SHA256, "trigger_if_missing": False},
                     "GET", re.escape(f"{API_BASE}/v1/capa-analysis/results/latest"),
                     {"capabilities": {"rules": {}}}),
            ToolSpec("threatray_get_ai_analysis", {"file_hash": SHA256, "trigger_if_missing": False},
                     "GET", re.escape(f"{API_BASE}/v1/ai-analysis/results"),
                     {"results": [{"id": "ai1", "summary": "..."}]}),
            ToolSpec("threatray_list_ai_analyses", {"file_hash": SHA256},
                     "GET", re.escape(f"{API_BASE}/v1/ai-analysis/results"),
                     {"results": []}),
            ToolSpec("threatray_download_file", {"file_hash": SHA256, "output_path": self._tmpfile(suffix=".zip")},
                     "GET", re.escape(f"{API_BASE}/v1/files/{SHA256}/data") + r".*",
                     None, b"PK\x03\x04"),
            ToolSpec("threatray_submit_sample", {"file_path": sample},
                     "POST", re.escape(f"{API_BASE}/v1/submissions/samples"),
                     {"submissions": [{"task_id": "s1", "status": "pending"}]}),
            ToolSpec("threatray_submit_url", {"url": "https://example.com/x"},
                     "POST", re.escape(f"{API_BASE}/v1/submissions/urls"),
                     {"submissions": [{"task_id": "u1", "status": "pending"}]}),
            ToolSpec("threatray_submit_endpoint_scan_archive", {"file_path": sample},
                     "POST", re.escape(f"{API_BASE}/v1/submissions/endpoint-scan-archive"),
                     {"submissions": [{"task_id": "ea1", "status": "pending"}]}),
            ToolSpec("threatray_submit_minidump", {"file_path": sample},
                     "POST", re.escape(f"{API_BASE}/v1/submissions/minidump"),
                     {"submissions": [{"task_id": "md1", "status": "pending"}]}),
            ToolSpec("threatray_submit_mans_file", {"file_path": sample},
                     "POST", re.escape(f"{API_BASE}/v1/submissions/mans-file"),
                     {"submissions": [{"task_id": "mf1", "status": "pending"}]}),
            ToolSpec("threatray_get_task", {"task_id": 42},
                     "GET", re.escape(f"{API_BASE}/v1/tasks/42"),
                     {"task_id": 42, "status": "done", "submission_id": "s1"}),
            ToolSpec("threatray_get_task_by_analysis", {"analysis_id": ANALYSIS_ID},
                     "GET", re.escape(f"{API_BASE}/v1/tasks/by-analysis/{ANALYSIS_ID}"),
                     {"task_id": 99, "status": "done", "submission_id": "s2"}),
            ToolSpec("threatray_list_tasks", {},
                     "GET", re.escape(f"{API_BASE}/v1/tasks"),
                     {"tasks": []}),
            ToolSpec("threatray_list_analyses", {},
                     "GET", re.escape(f"{API_BASE}/v1/analyses/samples"),
                     {"analyses": [], "cursor": None}),
            ToolSpec("threatray_list_endpoint_scan_analyses", {},
                     "GET", re.escape(f"{API_BASE}/v1/analyses/endpoint-scans"),
                     {"analyses": [], "cursor": None}),
            ToolSpec("threatray_get_ai_analysis_by_id", {"analysis_id": ANALYSIS_ID},
                     "GET", re.escape(f"{API_BASE}/v1/ai-analysis/results/{ANALYSIS_ID}"),
                     {"id": ANALYSIS_ID, "summary": "..."}),
            ToolSpec("threatray_get_latest_ai_job", {"file_hash": SHA256},
                     "GET", re.escape(f"{API_BASE}/v1/ai-analysis/jobs/latest"),
                     {"job_id": "j1", "job_status": "DONE"}),
        ]

    async def test_every_tool_has_happy_path(self):
        specs = self._specs()
        mcp = create_server()
        async with Client(mcp) as client:
            registered_tools = {t.name for t in await client.list_tools()}
            self.assertEqual(
                {s.name for s in specs}, registered_tools,
                "spec list and registered tools must match — update test_all_tools_smoke when adding/removing tools",
            )
            # Per-spec mock scope so two tools that share an upstream URL (e.g.
            # get_ai_analysis and list_ai_analyses both hit /v1/ai-analysis/results)
            # don't trample each other's expected responses.
            for spec in specs:
                with self.subTest(tool=spec.name):
                    with respx.mock(assert_all_called=False) as router:
                        if spec.response_bytes is not None:
                            router.route(method=spec.method, url__regex=spec.path_regex).mock(
                                return_value=httpx.Response(200, content=spec.response_bytes)
                            )
                        else:
                            router.route(method=spec.method, url__regex=spec.path_regex).mock(
                                return_value=httpx.Response(200, json=spec.response_json)
                            )
                        result = await client.call_tool(spec.name, {"params": spec.params})
                    self.assertTrue(
                        result.content and result.content[0].text,
                        f"{spec.name} returned empty content",
                    )
