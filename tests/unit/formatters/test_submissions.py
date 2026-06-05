"""Tests for formatters/submissions.py."""

import unittest

from hamcrest import assert_that, contains_string

from threatray_mcp.formatters import format_task, format_tasks_list


class TestFormatTask(unittest.TestCase):
    def test_single_task(self):
        data = {
            "task_id": 42,
            "status": "done",
            "submission_id": "s-1",
            "username": "alice",
            "sample": {"hash_sha256": "a" * 64, "file_name": "x.exe"},
            "analysis": {
                "id": "00000000-0000-0000-0000-000000000001",
                "verdict": "malicious",
                "threats": ["Emotet"],
            },
        }
        result = format_task(data)
        assert_that(result, contains_string("Task `42`"))
        assert_that(result, contains_string("done"))
        assert_that(result, contains_string("alice"))
        assert_that(result, contains_string("x.exe"))
        assert_that(result, contains_string("Emotet"))

    def test_list_response_unwraps_first(self):
        """`/v1/tasks/by-analysis/{id}` returns a list — the formatter renders
        the first entry and notes the sibling count when there are more."""
        data = [
            {
                "task_id": 42,
                "status": "done",
                "submission_id": "s-1",
                "sample": {"hash_sha256": "a" * 64},
                "analysis": {"id": "00000000-0000-0000-0000-000000000001", "verdict": "malicious"},
            },
            {
                "task_id": 43,
                "status": "done",
                "submission_id": "s-1",
                "sample": {"hash_sha256": "a" * 64},
                "analysis": {"id": "00000000-0000-0000-0000-000000000001", "verdict": "malicious"},
            },
        ]
        result = format_task(data)
        assert_that(result, contains_string("Task `42`"))
        assert_that(result, contains_string("Analysis produced 2 tasks"))

    def test_list_response_single_item_no_note(self):
        result = format_task([{"task_id": 7, "status": "done", "submission_id": "s-1"}])
        assert_that(result, contains_string("Task `7`"))
        # The "Analysis produced N tasks" sibling note must not appear.
        self.assertNotIn("Analysis produced", result)

    def test_empty_list_renders_empty_marker(self):
        result = format_task([])
        assert_that(result, contains_string("No task found"))

class TestFormatTasksList(unittest.TestCase):
    def test_empty_tasks(self):
        result = format_tasks_list({"tasks": []})
        assert_that(result, contains_string("Tasks: 0 found"))

    def test_renders_table(self):
        data = {
            "tasks": [
                {
                    "task_id": 1,
                    "status": "done",
                    "sample": {"file_name": "a.bin", "verdict": "suspicious"},
                    "analysis": {"threats": ["TestThreat"]},
                    "created_at": 123,
                }
            ]
        }
        result = format_tasks_list(data)
        # Columns now include Analysis ID + Submitter alongside the existing ones.
        assert_that(result, contains_string("| `1` | `-` | done"))
        assert_that(result, contains_string("a.bin"))
        assert_that(result, contains_string("TestThreat"))

    def test_caps_rendered_rows_at_limit(self):
        """If the backend returns more rows than the caller's `limit`
        (over-broad response), the formatter renders at most `limit` rows
        and reports the overflow in the header — the MCP response stays
        bounded and the discrepancy isn't hidden."""
        data = {"tasks": [{"task_id": i} for i in range(50)]}
        result = format_tasks_list(data, limit=5)
        # Header reflects the truncation.
        assert_that(result, contains_string("5 shown (of 50 returned)"))
        # Only the first 5 task IDs land in the table.
        for i in range(5):
            assert_that(result, contains_string(f"| `{i}` |"))
        self.assertNotIn("| `5` |", result)
        self.assertNotIn("| `49` |", result)
        # Overflow note present.
        assert_that(result, contains_string("Render cap: 5"))

    def test_no_cap_note_when_within_limit(self):
        data = {"tasks": [{"task_id": 1}, {"task_id": 2}]}
        result = format_tasks_list(data, limit=10)
        self.assertNotIn("Render cap", result)
        self.assertNotIn("shown (of", result)
