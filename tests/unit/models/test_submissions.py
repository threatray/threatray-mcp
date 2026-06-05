"""Tests for models/submissions.py inputs."""

import unittest

import pytest
from hamcrest import assert_that, contains_string, equal_to, has_length
from pydantic import ValidationError

from tests.dummies import DUMMY_MD5
from threatray_mcp.models import (
    SubmissionStatus,
    SubmitSampleInput,
    SubmitUrlInput,
    TaskIdInput,
    TasksListInput,
)


class TestSubmitSampleInputCrossFieldValidation(unittest.TestCase):
    def test_raw_binary_fields_require_format(self):
        with pytest.raises(ValidationError) as exc:
            SubmitSampleInput(file_path="/tmp/a.bin", raw_binary_cpu_architecture="x86-64")
        assert_that(str(exc.value), contains_string("raw_binary_file_format"))

    def test_raw_binary_minimal_valid(self):
        result = SubmitSampleInput(file_path="/tmp/a.bin", raw_binary_file_format="pe")
        assert_that(result.raw_binary_file_format, equal_to("pe"))

    def test_raw_binary_file_offset_requires_detection_disabled(self):
        with pytest.raises(ValidationError) as exc:
            SubmitSampleInput(
                file_path="/tmp/a.bin",
                raw_binary_file_format="raw",
                raw_binary_function_file_offset="0x1234",
            )
        assert_that(str(exc.value), contains_string("entry_point_detection_needed=false"))

    def test_compound_sample_requires_entry_point(self):
        with pytest.raises(ValidationError) as exc:
            SubmitSampleInput(file_path="/tmp/a.zip", is_compound_sample=True)
        assert_that(str(exc.value), contains_string("entry_point"))

    def test_compound_sample_with_entry_point_ok(self):
        result = SubmitSampleInput(
            file_path="/tmp/a.zip", is_compound_sample=True, entry_point="bin/main.exe"
        )
        assert_that(result.entry_point, equal_to("bin/main.exe"))

    def test_dll_exports_arguments_length_mismatch_rejected(self):
        with pytest.raises(ValidationError) as exc:
            SubmitSampleInput(
                file_path="/tmp/a.dll", dll_exports=["x", "y"], dll_arguments=["a"]
            )
        assert_that(str(exc.value), contains_string("same length"))

    def test_dll_exports_arguments_matched(self):
        result = SubmitSampleInput(
            file_path="/tmp/a.dll", dll_exports=["x"], dll_arguments=["arg1"]
        )
        assert_that(result.dll_exports, equal_to(["x"]))

    def test_invalid_analysis_mode_rejected(self):
        with pytest.raises(ValidationError):
            SubmitSampleInput(file_path="/tmp/a.bin", analysis_mode="hybrid")

    def test_invalid_priority_rejected(self):
        with pytest.raises(ValidationError):
            SubmitSampleInput(file_path="/tmp/a.bin", priority="urgent")

    def test_timeout_bounds(self):
        with pytest.raises(ValidationError):
            SubmitSampleInput(file_path="/tmp/a.bin", timeout_seconds=10)
        with pytest.raises(ValidationError):
            SubmitSampleInput(file_path="/tmp/a.bin", timeout_seconds=1501)

    def test_raw_binary_invalid_format_rejected(self):
        with pytest.raises(ValidationError):
            SubmitSampleInput(file_path="/tmp/a.bin", raw_binary_file_format="elf")

    def test_raw_binary_invalid_cpu_arch_rejected(self):
        with pytest.raises(ValidationError):
            SubmitSampleInput(
                file_path="/tmp/a.bin",
                raw_binary_file_format="raw",
                raw_binary_cpu_architecture="arm64",
            )

class TestSubmitUrlInput(unittest.TestCase):
    def test_http_accepted(self):
        result = SubmitUrlInput(url="http://example.com/x")
        assert_that(result.url, equal_to("http://example.com/x"))

    def test_https_accepted(self):
        result = SubmitUrlInput(url="https://example.com/x")
        assert_that(result.url, equal_to("https://example.com/x"))

    def test_ftp_accepted(self):
        result = SubmitUrlInput(url="ftp://example.com/x")
        assert_that(result.url, equal_to("ftp://example.com/x"))

    def test_scheme_required(self):
        with pytest.raises(ValidationError):
            SubmitUrlInput(url="example.com/no-scheme")

    def test_strips_whitespace(self):
        result = SubmitUrlInput(url="  https://example.com  ")
        assert_that(result.url, equal_to("https://example.com"))

class TestSubmissionStatusEnum(unittest.TestCase):
    def test_enum_values_mirror_openapi(self):
        # OpenAPI says: [queued, analyzing, failed, done, unsupported]
        assert_that(SubmissionStatus.ALL.value, equal_to(""))
        assert_that(SubmissionStatus.QUEUED.value, equal_to("queued"))
        assert_that(SubmissionStatus.ANALYZING.value, equal_to("analyzing"))
        assert_that(SubmissionStatus.DONE.value, equal_to("done"))
        assert_that(SubmissionStatus.FAILED.value, equal_to("failed"))
        assert_that(SubmissionStatus.UNSUPPORTED.value, equal_to("unsupported"))

    def test_str_enum_serialises_as_value(self):
        # httpx URL-encodes via str() — must yield the value, not the repr
        assert_that(str(SubmissionStatus.QUEUED), equal_to("queued"))

class TestTaskInputs(unittest.TestCase):
    def test_task_id_must_be_positive(self):
        with pytest.raises(ValidationError):
            TaskIdInput(task_id=0)

    def test_tasks_list_hash_validated(self):
        with pytest.raises(ValidationError):
            TasksListInput(file_hash="not-a-hash")

    def test_tasks_list_hash_md5_ok(self):
        result = TasksListInput(file_hash=DUMMY_MD5)
        assert_that(result.file_hash, has_length(32))
