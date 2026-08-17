"""Tests for AI-analysis job status presentation."""

import unittest
from datetime import datetime, timedelta, timezone

from threatray_mcp.ai_analysis_status import (
    ai_analysis_stage_label,
    ai_analysis_stage_step,
    format_ai_analysis_elapsed,
    format_ai_analysis_job_progress,
    format_ai_analysis_remaining,
)


class TestAiAnalysisStatus(unittest.TestCase):
    def test_stage_titles_and_steps_match_ui(self):
        cases = (
            ("PREPARING", "Preparing analysis", "Step 1 of 4"),
            ("DECOMPILING", "Decompiling code", "Step 2 of 4"),
            ("ANALYZING", "Analyzing functions", "Step 3 of 4"),
            ("SYNTHESIZING", "Finalizing results", "Step 4 of 4"),
        )

        for stage, title, step in cases:
            with self.subTest(stage=stage):
                self.assertEqual(ai_analysis_stage_label(stage), title)
                self.assertEqual(ai_analysis_stage_step({"stage": stage}), step)

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
        self.assertEqual(format_ai_analysis_elapsed(job, now=now), "1:12")
        self.assertEqual(format_ai_analysis_remaining(job), "1\N{EN DASH}7m left")
        self.assertEqual(ai_analysis_stage_step(job), "Step 2 of 4")

    def test_progress_message_falls_back_when_eta_is_unavailable(self):
        job = {
            "job_status": "PROCESSING",
            "stage": "PREPARING",
            "started_at": "not-a-timestamp",
            "remaining_time_estimate": None,
        }

        self.assertEqual(
            format_ai_analysis_job_progress(job),
            "AI analysis: Preparing analysis · Step 1 of 4",
        )

    def test_progress_message_matches_ui_copy_and_order(self):
        job = {
            "job_status": "PROCESSING",
            "stage": "ANALYZING",
            "started_at": (datetime.now(timezone.utc) - timedelta(seconds=72)).isoformat(),
            "remaining_time_estimate": {
                "minimum_seconds": 42,
                "maximum_seconds": 96,
            },
        }

        self.assertEqual(ai_analysis_stage_label(job["stage"]), "Analyzing functions")
        self.assertEqual(
            format_ai_analysis_job_progress(job),
            "AI analysis: Analyzing functions · Step 3 of 4 · 40s\N{EN DASH}2m left · 1:12 elapsed",
        )

    def test_queued_and_unknown_stage_titles_match_ui(self):
        self.assertEqual(format_ai_analysis_job_progress({"job_status": "QUEUED"}), "AI analysis: Analysis queued")
        self.assertEqual(
            format_ai_analysis_job_progress({"job_status": "PROCESSING", "stage": "NEW_STAGE"}),
            "AI analysis: Analyzing",
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
                    "job_status": "PROCESSING",
                    "remaining_time_estimate": {
                        "minimum_seconds": 120,
                        "maximum_seconds": 60,
                    },
                }
            )
        )

    def test_eta_rounding_matches_ui(self):
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
            "1m left",
        )

    def test_float_eta_bounds_are_accepted_and_rounded_like_ui(self):
        self.assertEqual(
            format_ai_analysis_remaining(
                {
                    "job_status": "processing",
                    "remaining_time_estimate": {
                        "minimum_seconds": 61.2,
                        "maximum_seconds": 119.1,
                    },
                }
            ),
            "1\N{EN DASH}2m left",
        )

    def test_boolean_eta_bound_is_rejected(self):
        self.assertIsNone(
            format_ai_analysis_remaining(
                {
                    "job_status": "PROCESSING",
                    "remaining_time_estimate": {
                        "minimum_seconds": True,
                        "maximum_seconds": 120,
                    },
                }
            )
        )

    def test_lowercase_processing_status_keeps_elapsed_time(self):
        self.assertEqual(
            format_ai_analysis_elapsed(
                {
                    "job_status": "processing",
                    "started_at": "2026-08-17T09:58:48Z",
                },
                now=datetime(2026, 8, 17, 10, 0, tzinfo=timezone.utc),
            ),
            "1:12",
        )

    def test_elapsed_over_an_hour_matches_ui_minute_clock(self):
        self.assertEqual(
            format_ai_analysis_elapsed(
                {
                    "job_status": "PROCESSING",
                    "started_at": "2026-08-17T09:00:00Z",
                },
                now=datetime(2026, 8, 17, 10, 0, tzinfo=timezone.utc),
            ),
            "60:00",
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

    def test_missing_estimate_matches_ui_stage_messaging(self):
        self.assertIsNone(format_ai_analysis_remaining({"job_status": "PROCESSING", "stage": "PREPARING"}))
        self.assertEqual(
            format_ai_analysis_remaining({"job_status": "PROCESSING", "stage": "DECOMPILING"}),
            "Taking longer than expected",
        )
