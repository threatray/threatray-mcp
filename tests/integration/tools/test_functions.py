"""Integration tool tests for the functions section — full path via
fastmcp.Client + respx-mocked upstream."""

import unittest

import httpx
import respx
from fastmcp import Client

from tests.dummies import DUMMY_SAMPLE_ANALYSIS_ID, DUMMY_SHA256, DUMMY_SHA256_B
from threatray_mcp.server import create_server

API_BASE = "https://api.threatray.test"


class TestListFunctionsTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_list_functions_returns_function_table(self):
        respx.get(f"{API_BASE}/v1/functions/{DUMMY_SHA256}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "functions": [
                        {
                            "uid": "CFF.1234567890",
                            "code_region": DUMMY_SHA256[:8],
                            "address": 0x401000,
                            "verdict": "malicious",
                            "function_size": 256,
                        }
                    ]
                },
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_list_functions", {"params": {"file_hash": DUMMY_SHA256}}
            )
        text = result.content[0].text
        self.assertIn("CFF.1234567890", text)


class TestGetCodeDetectionsTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_code_detections_render_signature_matches(self):
        respx.get(f"{API_BASE}/v1/functions/code-detections").mock(
            return_value=httpx.Response(
                200,
                json={
                    "functions": [
                        {
                            "analysis_id": DUMMY_SAMPLE_ANALYSIS_ID,
                            "code_region": DUMMY_SHA256[:8],
                            "pid": 0,
                            "base": 0,
                            "uid": "EFF.1",
                            "address": 0x401000,
                            "verdict": "malicious",
                            "code_detections": [
                                {
                                    "verdict": "malicious",
                                    "score": 0.9,
                                    "code_signature": {"name": "Emotet_loader"},
                                    "family": {"name": "Emotet", "category": "malware"},
                                }
                            ],
                        }
                    ]
                },
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_get_code_detections",
                {"params": {"hash_sha256": DUMMY_SHA256}},
            )
        text = result.content[0].text
        self.assertIn("Emotet", text)


class TestRetrohuntFunctionsTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_retrohunt_passes_uids(self):
        route = respx.get(f"{API_BASE}/v1/retrohunt/functions").mock(
            return_value=httpx.Response(
                200,
                json={"functions": [], "code_regions": [], "samples": [], "analyses": []},
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            await client.call_tool(
                "threatray_retrohunt_functions",
                {"params": {"function_uids": ["CFF.111", "CFF.222"]}},
            )
        # uids land in the query string verbatim.
        self.assertEqual(
            route.calls[0].request.url.params.get_list("uids"), ["CFF.111", "CFF.222"]
        )

    @respx.mock
    async def test_retrohunt_uses_function_style_formatter(self):
        """Regression for the swap PR9630-era bug where the tool was wired to
        `format_retrohunt_results` (sample-style) instead of
        `format_function_retrohunt`. Lock the function-style markers in the
        output so a future swap back trips immediately."""
        ref_uid = "CFF.5407282157109570886"
        matched_uid = "CFF.-3800300172407233952"
        region_hash = "1" * 64
        sample_hash = "7" * 64
        analysis_id = "00000000-0000-0000-0000-000000000003"
        respx.get(f"{API_BASE}/v1/retrohunt/functions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "functions": [
                        {
                            "uid": ref_uid,
                            "matches": [
                                {
                                    "code_region": region_hash,
                                    "analysis_id": analysis_id,
                                    "pid": 0,
                                    "base": 0,
                                    "address": 0x1000,
                                    "uid": matched_uid,
                                    "score": 0.99,
                                    "confidence": "high",
                                    "similarity": "high",
                                }
                            ],
                        }
                    ],
                    "code_regions": [
                        {
                            "analysis_id": analysis_id,
                            "hash_sha256": region_hash,
                            "verdict": "malicious",
                            "threats": [{"label": "Emotet", "confidence": "high"}],
                            "nr_of_function_matches": 1,
                            "function_count": 25,
                        }
                    ],
                    "samples": [
                        {
                            "hash_sha256": sample_hash,
                            "analysis_id": analysis_id,
                            "verdict": "malicious",
                            "threats": [{"label": "Emotet", "confidence": "high"}],
                        }
                    ],
                    "analyses": [],
                },
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_retrohunt_functions",
                {"params": {"function_uids": [ref_uid]}},
            )
        text = result.content[0].text
        # Function-style heading + region-pivoted table — these only come
        # from `format_function_retrohunt`, never from `format_retrohunt_results`.
        self.assertIn("Function Retrohunt:", text)
        self.assertIn(f"**Input UIDs (1):** `{ref_uid}`", text)
        # Per-region row carries the full sample SHA256.
        self.assertIn(sample_hash, text)
        # Code-region cell: 1 ref UID matched. Region function count is
        # intentionally omitted from the cell (denominator ambiguity).
        self.assertIn("1/1 ref UIDs", text)
        self.assertNotIn("funcs", text)
        # Matching-functions cell: ref → matched UID @ addr · score · conf · sim.
        self.assertIn(
            f"`{ref_uid}` → `{matched_uid}` @ `0x00001000` · 0.99 · high · high",
            text,
        )
        # The sample-style headings must NOT appear.
        self.assertNotIn("Similar Samples:", text)
        self.assertNotIn("Sample details", text)


class TestDiffFunctionsTool(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_diff_returns_matches(self):
        respx.post(f"{API_BASE}/v1/functions/diff").mock(
            return_value=httpx.Response(
                200,
                json={
                    "source_file": {
                        "hash_sha256": DUMMY_SHA256,
                        "verdict": "malicious",
                        "threats": [{"label": "Emotet", "confidence": "high"}],
                        "function_count": 200,
                    },
                    "files": [
                        {
                            "hash_sha256": DUMMY_SHA256_B,
                            "verdict": "malicious",
                            "threats": [{"label": "Emotet", "confidence": "high"}],
                            "function_count": 180,
                        }
                    ],
                    "functions": [
                        {
                            "uid": "CFF.source-1",
                            "address": 0x401000,
                            "matches": [
                                {
                                    "uid": "CFF.matched-1",
                                    "address": 0x501000,
                                    "hash_sha256": DUMMY_SHA256_B,
                                    "score": 0.99,
                                    "confidence": "high",
                                    "similarity": "high",
                                }
                            ],
                        }
                    ],
                },
            )
        )
        mcp = create_server()
        async with Client(mcp) as client:
            result = await client.call_tool(
                "threatray_diff_functions",
                {"params": {"source_hash": DUMMY_SHA256, "target_hashes": [DUMMY_SHA256_B]}},
            )
        text = result.content[0].text
        # Full source SHA256 surfaces in the Source metadata block.
        self.assertIn(DUMMY_SHA256, text)
        # Full target SHA256 surfaces in the targets table and match table.
        self.assertIn(DUMMY_SHA256_B, text)
        # Match details carry score/confidence/similarity.
        self.assertIn("0.99", text)
        self.assertIn("high", text)
        # Score/Conf/Sim header is the diff signature.
        self.assertIn("| Score | Conf | Sim |", text)
