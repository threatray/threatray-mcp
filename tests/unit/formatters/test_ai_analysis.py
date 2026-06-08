"""Tests for formatters/ai_analysis.py — the three AI-result shapes (trigger ack,
job-status, list entry, full detail) plus the listing endpoint."""

import unittest

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
        data = {
            "job_id": "job-1",
            "file_hash": DUMMY_SHA256,
            "job_status": "PROCESSING",
        }
        result = format_ai_analysis(data)
        assert_that(result, contains_string("AI Analysis Job"))
        assert_that(result, contains_string("PROCESSING"))

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
            {"functions_analyzed": 0, "functions_decompiled": 0,
             "created_at": "2026-05-20T09:55:06Z"}
        )
        assert_that(result, contains_string("0 analysed"))
        assert_that(result, is_not(contains_string("? analysed")))
