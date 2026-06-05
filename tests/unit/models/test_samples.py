"""Tests for models/samples.py inputs."""

import unittest

import pytest
from hamcrest import assert_that, has_length
from pydantic import ValidationError

from tests.dummies import DUMMY_MD5, DUMMY_SHA1, DUMMY_SHA256
from threatray_mcp.models import SampleHashInput


class TestSampleHashInput(unittest.TestCase):
    def test_valid_md5_hash(self):
        result = SampleHashInput(sample_hash=DUMMY_MD5)
        assert_that(result.sample_hash, has_length(32))

    def test_valid_sha1_hash(self):
        result = SampleHashInput(sample_hash=DUMMY_SHA1)
        assert_that(result.sample_hash, has_length(40))

    def test_valid_sha256_hash(self):
        result = SampleHashInput(sample_hash=DUMMY_SHA256)
        assert_that(result.sample_hash, has_length(64))

    def test_invalid_hash_characters(self):
        with pytest.raises(ValidationError):
            SampleHashInput(sample_hash="zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")

    def test_hash_too_short(self):
        with pytest.raises(ValidationError):
            SampleHashInput(sample_hash="abc123")

    def test_hash_too_long(self):
        with pytest.raises(ValidationError):
            SampleHashInput(sample_hash="a" * 65)
