"""Tests for formatters/ai_analysis.py — the three AI-result shapes (trigger ack,
job-status, list entry, full detail) plus the listing endpoint."""

import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone

from hamcrest import assert_that, contains_string, is_not

from tests.dummies import DUMMY_AI_ANALYSIS_ID, DUMMY_SHA256
from threatray_mcp.formatters import format_ai_analysis, format_ai_analysis_list


class TestFormatAiAnalysisListing(unittest.TestCase):
    def test_empty(self):
        result = format_ai_analysis_list({"results": []})
        assert_that(result, contains_string("AI Analyses: 0 found"))
        assert_that(result, contains_string("No AI analysis"))

    def test_renders_rows(self):
        data = {
            "results": [
                {
                    "id": DUMMY_AI_ANALYSIS_ID,
                    "file_hash": DUMMY_SHA256,
                    "verdict": "suspicious",
                    "functions_analyzed": 5,
                    "created_at": "2026-05-20T09:55:06Z",
                }
            ]
        }
        result = format_ai_analysis_list(data)
        assert_that(result, contains_string("AI Analyses: 1 found"))
        assert_that(result, contains_string(DUMMY_AI_ANALYSIS_ID))
        assert_that(result, contains_string("suspicious"))
        # ISO inputs now re-emit in the same `YYYY-MM-DD HH:MM:SS UTC` form
        # epoch inputs produce, so every tool's full-datetime is uniform.
        assert_that(result, contains_string("2026-05-20 09:55:06 UTC"))


class TestFormatAiAnalysisDetail(unittest.TestCase):
    def test_full_result(self):
        data = {
            "id": DUMMY_AI_ANALYSIS_ID,
            "file_hash": DUMMY_SHA256,
            "verdict": "suspicious",
            "assessment": "Loader with XOR-based decryption and dynamic API resolution.",
            "capabilities": [
                {
                    "category": "decryption",
                    "title": "Inline Data Decryption",
                    "description": "XOR-based decryption routines.",
                }
            ],
            "functions": [
                {
                    "address": 5369168224,
                    "verdict": "suspicious",
                    "explanation": "Performs dynamic API resolution.",
                }
            ],
            "functions_analyzed": 5,
            "functions_decompiled": 5,
            "created_at": "2026-05-20T09:55:06Z",
        }
        result = format_ai_analysis(data)
        assert_that(result, contains_string("AI Analysis"))
        assert_that(result, contains_string("suspicious"))
        assert_that(result, contains_string("Loader with XOR-based decryption"))
        assert_that(result, contains_string("Inline Data Decryption"))
        # 5369168224 → 0x140070160
        assert_that(result, contains_string("0x140070160"))
        assert_that(result, contains_string("dynamic API resolution"))

    def test_trigger_only_ack(self):
        data = {
            "job": {
                "job_id": "job-1",
                "file_hash": DUMMY_SHA256,
                "job_status": "QUEUED",
            },
            "pending": True,
        }
        result = format_ai_analysis(data)
        assert_that(result, contains_string("AI Analysis Job — queued"))
        assert_that(result, contains_string("job-1"))
        assert_that(result, contains_string("QUEUED"))

    def test_latest_job_shape(self):
        """`/v1/ai-analysis/jobs/latest` returns the job dict directly."""
        started_at = datetime.now(timezone.utc) - timedelta(seconds=90)
        data = {
            "job_id": "job-1",
            "file_hash": DUMMY_SHA256,
            "job_status": "PROCESSING",
            "created_at": "2026-08-17T09:58:00Z",
            "started_at": started_at.isoformat(),
            "stage": "DECOMPILING",
            "remaining_time_estimate": {
                "minimum_seconds": 84,
                "maximum_seconds": 399,
            },
        }
        result = format_ai_analysis(data)
        assert_that(result, contains_string("AI Analysis Job"))
        assert_that(result, contains_string("PROCESSING"))
        assert_that(result, contains_string("Decompiling code"))
        assert_that(result, contains_string("Step 2 of 4"))
        assert_that(result, contains_string("Elapsed"))
        assert_that(result, contains_string("1\N{EN DASH}7m left"))

    def test_latest_completed_job_includes_exact_result_id_without_live_elapsed(self):
        data = {
            "job_id": "job-1",
            "file_hash": DUMMY_SHA256,
            "job_status": "DONE",
            "started_at": "2026-08-17T09:58:00Z",
            "stage": "SYNTHESIZING",
            "result_id": DUMMY_AI_ANALYSIS_ID,
        }

        result = format_ai_analysis(data)

        assert_that(result, contains_string(DUMMY_AI_ANALYSIS_ID))
        assert_that(result, contains_string("Finalizing results"))
        assert_that(result, is_not(contains_string("Step 4 of 4")))
        assert_that(result, is_not(contains_string("Elapsed")))

    def test_listing_summary_shape(self):
        """`results[i]` from `/v1/ai-analysis/results` is shorter — no
        `assessment`/`functions`/`verdict`. Render as a summary card with a
        hint to fetch the full detail."""
        data = {
            "id": DUMMY_AI_ANALYSIS_ID,
            "file_hash": DUMMY_SHA256,
            "functions_analyzed": 5,
            "created_at": "2026-05-20T09:55:06Z",
        }
        result = format_ai_analysis(data)
        assert_that(result, contains_string("AI Analysis (summary)"))
        assert_that(result, contains_string("get_ai_analysis_by_id"))


class TestZeroFunctionsAnalysed(unittest.TestCase):
    def test_zero_functions_renders_zero_not_question_mark(self):
        # 0 functions analysed is a real result, not "unknown" — render 0, not ?.
        result = format_ai_analysis(
            {"functions_analyzed": 0, "functions_decompiled": 0, "created_at": "2026-05-20T09:55:06Z"}
        )
        assert_that(result, contains_string("0 analysed"))
        assert_that(result, is_not(contains_string("? analysed")))


class TestAiAnalysisWarnings(unittest.TestCase):
    def test_warnings_preserve_order_duplicates_and_assessment(self) -> None:
        for verdict in ("unknown", "malicious", "suspicious", "benign"):
            data = {
                "verdict": verdict,
                "assessment": "Looks benign.",
                "warnings": ["Limited.", "Other.", "Limited.", ""],
                "function_coverage": {"truncated": True},
                "functions_analyzed": 0,
                "functions_decompiled": 0,
            }
            before = deepcopy(data)
            result = format_ai_analysis(data)
            self.assertEqual(data, before)
            self.assertIn(f"**Verdict**: {verdict}", result)
            self.assertIn("**Coverage truncated**: true", result)
            self.assertIn("### Summary (LLM-generated)\nLooks benign.", result)
            self.assertEqual(result.count("Limited."), 2)
            self.assertLess(result.index("Limited."), result.index("Other."))
            self.assertLess(result.index("Warning 4:"), result.index("### Summary"))
            self.assertIn("Warning 4:\n```text\n\n```", result)

    def test_coverage_states_in_full_and_list(self) -> None:
        for fields, label in (
            ({"function_coverage": {"truncated": True}}, "true"),
            ({"function_coverage": {"truncated": False}}, "false"),
            ({"function_coverage": {"truncated": None}}, "unknown (null)"),
            ({}, "unknown (not supplied)"),
        ):
            with self.subTest(fields=fields):
                detail = format_ai_analysis({"assessment": "text", **fields})
                listing = format_ai_analysis_list({"results": [{"id": "result", **fields}]})
                self.assertIn(f"**Coverage truncated**: {label}", detail)
                self.assertIn(f"| {label} |", listing)
                self.assertNotIn("Analysis warnings", listing)
                self.assertNotIn("Analysis warnings", detail)

    def test_absent_and_empty_warnings_do_not_invent_warning(self) -> None:
        for fields in ({}, {"warnings": []}):
            self.assertNotIn("Analysis warnings", format_ai_analysis({"assessment": "text", **fields}))

    def test_present_malformed_warnings_fail_clearly(self) -> None:
        for warnings in (None, "warning", ["valid", 1], {}, [None]):
            with self.subTest(warnings=warnings), self.assertRaisesRegex(ValueError, "warnings.*array of strings"):
                format_ai_analysis({"assessment": "text", "warnings": warnings})
