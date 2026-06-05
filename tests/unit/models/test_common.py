"""Tests for models/common.py inputs."""

import unittest

import pytest
from hamcrest import assert_that, has_length
from pydantic import ValidationError

from tests.dummies import DUMMY_MD5, DUMMY_SHA1, DUMMY_SHA256
from threatray_mcp.models import AiAnalysisInput, CapaInput


class TestHashSha256Strict(unittest.TestCase):
    """CapaInput / AiAnalysisInput use HashSha256 — must reject md5 + sha1."""

    def test_capa_accepts_sha256(self):
        result = CapaInput(file_hash=DUMMY_SHA256)
        assert_that(result.file_hash, has_length(64))

    def test_capa_rejects_md5(self):
        with pytest.raises(ValidationError):
            CapaInput(file_hash=DUMMY_MD5)

    def test_capa_rejects_sha1(self):
        with pytest.raises(ValidationError):
            CapaInput(file_hash=DUMMY_SHA1)

    def test_ai_accepts_sha256(self):
        result = AiAnalysisInput(file_hash=DUMMY_SHA256)
        assert_that(result.file_hash, has_length(64))

    def test_ai_rejects_md5(self):
        with pytest.raises(ValidationError):
            AiAnalysisInput(file_hash=DUMMY_MD5)
