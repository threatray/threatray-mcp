"""Tests for AI-analysis job status presentation."""

import unittest
from datetime import datetime, timezone

from threatray_mcp.ai_analysis_status import (
    ai_analysis_stage_label,
    format_ai_analysis_elapsed,
    format_ai_analysis_job_progress,
    format_ai_analysis_remaining,
)


class TestAiAnalysisStatus(unittest.TestCase):
    def test_formats_processing_progress_from_server_owned_fields(self):
        job = {
            "job_status": "PROCESSING",
            "stage": "DECOMPILING",
            "started_at": "2026-08-17T09:58:48Z",
            "remaining_time_estimate": {
                "minimum_seconds": 84,
                "maximum_seconds": 399,
            },
        }
        now = datetime(2026, 8, 17, 10, 0, tzinfo=timezone.utc)

        self.assertEqual(ai_analysis_stage_label(job["stage"]), "Decompiling code")
        self.assertEqual(format_ai_analysis_elapsed(job, now=now), "1m 12s")
        self.assertEqual(format_ai_analysis_remaining(job), "about 1m-7m remaining")

    def test_progress_message_falls_back_when_eta_is_unavailable(self):
        job = {
            "job_status": "PROCESSING",
            "stage": "PREPARING",
            "started_at": "not-a-timestamp",
            "remaining_time_estimate": None,
        }

        self.assertEqual(
            format_ai_analysis_job_progress(job),
            "AI analysis: Preparing · remaining time unavailable",
        )

    def test_elapsed_is_only_live_for_processing_jobs(self):
        job = {
            "job_status": "DONE",
            "started_at": "2026-08-17T09:58:48Z",
        }

        self.assertIsNone(
            format_ai_analysis_elapsed(
                job,
                now=datetime(2026, 8, 17, 10, 0, tzinfo=timezone.utc),
            )
        )

    def test_rejects_malformed_eta_ranges(self):
        self.assertIsNone(
            format_ai_analysis_remaining(
                {
                    "remaining_time_estimate": {
                        "minimum_seconds": 120,
                        "maximum_seconds": 60,
                    }
                }
            )
        )

    def test_eta_rounding_does_not_narrow_server_range(self):
        self.assertEqual(
            format_ai_analysis_remaining(
                {
                    "job_status": "PROCESSING",
                    "remaining_time_estimate": {
                        "minimum_seconds": 61,
                        "maximum_seconds": 61,
                    },
                }
            ),
            "about 1m-2m remaining",
        )

    def test_terminal_job_ignores_stale_eta(self):
        self.assertIsNone(
            format_ai_analysis_remaining(
                {
                    "job_status": "DONE",
                    "remaining_time_estimate": {
                        "minimum_seconds": 60,
                        "maximum_seconds": 120,
                    },
                }
            )
        )
