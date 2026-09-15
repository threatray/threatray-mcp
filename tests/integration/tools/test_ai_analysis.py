"""Integration tool tests — full path via fastmcp.Client + respx-mocked upstream."""

import re
import unittest
from itertools import pairwise

import httpx
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from threatray_mcp.server import create_server

API_BASE = "https://api.threatray.test"
SHA256 = "a" * 64


class TestAiAnalysisFeatureUnavailable(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_ai_analysis_404_surfaces_as_tool_error(self):
        """When AI analysis is disabled for the realm, /v1/ai-analysis/results 404s.
        Our section-client translates this to ThreatrayFeatureUnavailable; FastMCP
        wraps it into a ToolError visible to the MCP client (not a string-wrapped
        success that hides the failure)."""
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(404))
        mcp = create_server()
        async with Client(mcp) as client:
            with self.assertRaises(ToolError) as ctx:
                await client.call_tool(
                    "threatray_get_ai_analysis",
                    {"params": {"file_hash": SHA256, "trigger_if_missing": False}},
                )
        self.assertIn("AI analysis is not enabled", str(ctx.exception))


class TestAiAnalysisAbsenceMessages(unittest.IsolatedAsyncioTestCase):
    """The absence messages must survive the tool layer, not just the client.

    These stay `ToolError` deliberately: the package's documented error model is
    that failures surface as MCP tool errors rather than success-shaped strings.
    What changed is what they say, so that is what is asserted here.
    """

    @respx.mock
    async def test_latest_job_absence_answers_the_question_before_offering_a_job(self):
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/latest").mock(return_value=httpx.Response(404))
        mcp = create_server()
        async with Client(mcp) as client:
            with self.assertRaises(ToolError) as ctx:
                await client.call_tool(
                    "threatray_get_latest_ai_job", {"params": {"file_hash": SHA256}}
                )
        message = str(ctx.exception)
        self.assertIn("No AI analysis job was found for this file", message)
        self.assertIn("that is the answer", message)
        self.assertIn("starts an analysis job", message)
        # Order is the design, not decoration: the yes/no answer must precede the
        # costly action, or the message reads as "go create one" to the majority
        # who only wanted the answer. Substring assertions alone are satisfied by
        # a message that reverses them.
        self.assertLess(
            message.index("that is the answer"),
            message.index("starts an analysis job"),
            "the answer must come before the action that creates a job",
        )
        # True on a realm that serves no AI route at all. Asserted as an
        # invariant rather than as forbidden spellings: every mention of the
        # feature being enabled must be negated, and the message may say nothing
        # about an analysis having run or been created. A spelling ban is
        # defeated by "your account has AI analysis enabled, so no job has ever
        # been run", which asserts both falsehoods.
        #
        # The verbatim pin for these messages lives in the unit suite, in one
        # place. This copy deliberately guards the *claims* instead: two full-text
        # pins of the same string would have to be updated together, and the
        # recurring defect in this change has been updating one copy of a claim
        # and not the other.
        flat = " ".join(message.split())
        for match in re.finditer(r"\benabled\b", flat):
            self.assertTrue(
                flat[: match.start()].rstrip().endswith("not"),
                f"message claims the feature is enabled, which a 404 cannot establish: {flat!r}",
            )
        self.assertIsNone(re.search(r"\brun\b", flat), f"message claims an analysis ran: {flat!r}")
        self.assertIsNone(
            re.search(r"\bcreated\b", flat), f"message claims something was created: {flat!r}"
        )

    @respx.mock
    async def test_no_trigger_absence_names_the_opt_in(self):
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(
            return_value=httpx.Response(200, json={"results": []})
        )
        mcp = create_server()
        async with Client(mcp) as client:
            with self.assertRaises(ToolError) as ctx:
                await client.call_tool(
                    "threatray_get_ai_analysis",
                    {"params": {"file_hash": SHA256, "trigger_if_missing": False}},
                )
        message = str(ctx.exception)
        self.assertIn("No AI analysis results exist for this file", message)
        self.assertIn("trigger_only=true", message)

    async def test_annotations_do_not_advertise_idempotency_for_job_creation(self):
        """AI-analysis job creation is not deduplicated — two identical calls on a
        file with no result create two jobs and two analyses. Advertising
        idempotency would tell an MCP client that retrying is free. CAPA is the
        contrast: its creation is a get-or-create, so it keeps the hint."""
        mcp = create_server()
        async with Client(mcp) as client:
            tools = {t.name: t for t in await client.list_tools()}
        self.assertIs(tools["threatray_get_ai_analysis"].annotations.idempotentHint, False)
        # The contrast is load-bearing, so assert it rather than only asserting
        # it in prose: CAPA reuses an existing job, so retrying it really is free.
        self.assertIs(tools["threatray_get_capa"].annotations.idempotentHint, True)
        # Read-only tools are genuinely idempotent and must keep saying so.
        for name in ("threatray_get_latest_ai_job", "threatray_list_ai_analyses"):
            self.assertIs(tools[name].annotations.idempotentHint, True)

    async def test_latest_job_description_disclaims_existence_checks(self):
        """This route is reached as an existence check, which it is not. The
        description has to say so outright: it already said what the tool is
        *for*, and that alone did not stop the misuse."""
        mcp = create_server()
        async with Client(mcp) as client:
            tools = {t.name: t for t in await client.list_tools()}
        description = tools["threatray_get_latest_ai_job"].description or ""
        # Docstrings wrap, so a multi-word claim is not a literal substring of
        # the raw text. Collapse whitespace before asserting phrases.
        flat = " ".join(description.split())
        # This description is pinned in full, deliberately.
        #
        # No `assertIn`/`assertNotIn` pair can catch text *appended* after the
        # asserted phrase, and every claim in this description is load-bearing:
        # that it is not an existence check, that it reads the latest job rather
        # than the caller's, and above all that a not-found here stays ambiguous
        # and must not be read as proof the feature is on.
        #
        # So: changing this description is intended to fail this test. Update the
        # expected text deliberately, having re-checked that each claim is still
        # true of the code.
        expected = (
            "Read the latest AI analysis job for a file. **Not an existence check.** "
            "Use this after `threatray_get_ai_analysis(trigger_only=True)` hands back a "
            "job id: it reports `job_status`, whose terminal values are `DONE`, "
            "`FAILED`, `UNSUPPORTED` and `SKIPPED`, and a job still running carries its "
            "stage, start time and a nullable server-calculated remaining-time range. "
            "It looks up the *latest* "
            "job for the file, not one job by id, and job creation is not deduplicated "
            "— so where a file has several jobs this need not be the one you started. "
            "A not-found here is ambiguous and stays that way: it reports that no job "
            "was found, which on a deployment without AI analysis is indistinguishable "
            "from the feature being absent. To ask whether a file *has* an analysis, "
            "call `threatray_list_ai_analyses` — where AI analysis is enabled for your "
            "account it answers with an empty list rather than an error. To confirm the "
            "file itself exists, use `threatray_get_file_metadata`."
        )
        self.assertEqual(flat, expected)


class TestAiAnalysisProgress(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_blocking_tool_reports_indeterminate_progress(self):
        result_id = "00000000-0000-0000-0000-000000000001"
        respx.get(f"{API_BASE}/v1/ai-analysis/results").mock(return_value=httpx.Response(200, json={"results": []}))
        respx.post(f"{API_BASE}/v1/ai-analysis/jobs").mock(
            return_value=httpx.Response(200, json={"job_id": "j1", "job_status": "QUEUED"})
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/jobs/j1").mock(
            return_value=httpx.Response(
                200,
                json={"job_id": "j1", "job_status": "DONE", "result_id": result_id},
            )
        )
        respx.get(f"{API_BASE}/v1/ai-analysis/results/{result_id}").mock(
            return_value=httpx.Response(
                200,
                json={"id": result_id, "file_hash": SHA256, "assessment": "complete"},
            )
        )
        updates: list[tuple[float, float | None, str | None]] = []

        async def progress_handler(progress: float, total: float | None, message: str | None) -> None:
            updates.append((progress, total, message))

        mcp = create_server()
        async with Client(mcp, progress_handler=progress_handler) as client:
            await client.call_tool(
                "threatray_get_ai_analysis",
                {"params": {"file_hash": SHA256, "trigger_if_missing": True}},
            )

        self.assertTrue(updates)
        self.assertTrue(all(total is None for _, total, _ in updates))
        progress_values = [progress for progress, _, _ in updates]
        self.assertEqual(progress_values, [1.0, 2.0, 3.0, 4.0, 5.0])
        self.assertTrue(all(current < following for current, following in pairwise(progress_values)))
        self.assertTrue(any(progress == 4.0 and message == "AI analysis: Complete" for progress, _, message in updates))
