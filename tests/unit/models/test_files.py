"""Tests for models/files.py inputs."""

import unittest

import pytest
from hamcrest import assert_that, contains_string, equal_to, has_length
from pydantic import ValidationError

from tests.dummies import DUMMY_MD5, DUMMY_SHA256
from threatray_mcp.models import FileDownloadInput, FileMetadataInput, ResponseFormat, StringsInput


class TestFileDownloadInput(unittest.TestCase):
    def test_valid_download_path_tmp(self):
        result = FileDownloadInput(
            file_hash=DUMMY_SHA256,
            output_path="/tmp/sample.zip",
        )
        assert_that(result.output_path, contains_string("/tmp"))

    def test_valid_download_path_var_tmp(self):
        result = FileDownloadInput(
            file_hash=DUMMY_SHA256,
            output_path="/var/tmp/sample.zip",
        )
        assert_that(result.output_path, contains_string("/var/tmp"))

    def test_accepts_any_path_the_os_lets_us_write(self):
        """No directory allowlist any more (PR9630 #49867) — OS file-system
        permissions are the source of truth for where the MCP can write."""
        result = FileDownloadInput(
            file_hash=DUMMY_SHA256,
            output_path="/home/user/sample.zip",
        )
        assert_that(result.output_path, contains_string("/home/user/sample.zip"))

    def test_invalid_download_path_directory(self):
        with pytest.raises(ValidationError):
            FileDownloadInput(
                file_hash=DUMMY_SHA256,
                output_path="/tmp/",
            )


class TestFileMetadataInput(unittest.TestCase):
    def test_minimal_valid(self):
        result = FileMetadataInput(file_hash=DUMMY_SHA256)
        assert_that(result.file_hash, has_length(64))
        assert_that(result.response_format, equal_to(ResponseFormat.MARKDOWN))

    def test_accepts_md5_hash(self):
        result = FileMetadataInput(file_hash=DUMMY_MD5)
        assert_that(result.file_hash, has_length(32))

    def test_rejects_invalid_hash(self):
        with pytest.raises(ValidationError):
            FileMetadataInput(file_hash="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")

    def test_no_include_strings_field(self):
        """The model intentionally has no `include_strings` — strings live on
        the dedicated `threatray_get_strings` tool."""
        self.assertNotIn("include_strings", FileMetadataInput.model_fields)


class TestStringsInput(unittest.TestCase):
    def test_minimal_valid(self):
        result = StringsInput(file_hash=DUMMY_SHA256)
        assert_that(result.file_hash, has_length(64))
        assert_that(result.response_format, equal_to(ResponseFormat.MARKDOWN))

    def test_accepts_md5_hash(self):
        result = StringsInput(file_hash=DUMMY_MD5)
        assert_that(result.file_hash, has_length(32))

    def test_accepts_json_response_format(self):
        result = StringsInput(file_hash=DUMMY_SHA256, response_format="json")
        assert_that(result.response_format, equal_to(ResponseFormat.JSON))

    def test_rejects_invalid_hash(self):
        with pytest.raises(ValidationError):
            StringsInput(file_hash="not-a-hex-hash")
