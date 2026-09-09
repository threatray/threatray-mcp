"""Tests for models/capa.py inputs."""

import unittest
from uuid import UUID

import pytest
from hamcrest import assert_that, instance_of, is_
from pydantic import ValidationError

from threatray_mcp.models import CapaJobInput

JOB_ID = "00000000-0000-0000-0000-0000000000aa"


class TestCapaJobInput(unittest.TestCase):
    def test_valid_uuid(self):
        result = CapaJobInput(job_id=JOB_ID)
        assert_that(result.job_id, is_(instance_of(UUID)))

    def test_invalid_uuid(self):
        """The annotation is the only thing between a caller-supplied string and
        the job URL path, so relaxing it to `str` must not pass silently."""
        with pytest.raises(ValidationError):
            CapaJobInput(job_id="not-a-uuid")

    def test_path_shaped_input_is_rejected(self):
        with pytest.raises(ValidationError):
            CapaJobInput(job_id="../../v1/files/abc")
