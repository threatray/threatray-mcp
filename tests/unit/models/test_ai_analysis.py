"""Tests for models/ai_analysis.py inputs."""

import unittest

import pytest
from hamcrest import assert_that, equal_to
from pydantic import ValidationError

from tests.dummies import DUMMY_SHA256
from threatray_mcp.models import AiAnalysisInput


class TestAiAnalysisInputKnobs(unittest.TestCase):
    def test_defaults(self):
        result = AiAnalysisInput(file_hash=DUMMY_SHA256)
        assert_that(result.trigger_if_missing, equal_to(True))
        assert_that(result.trigger_only, equal_to(False))
        assert_that(result.max_wait_seconds, equal_to(600))

    def test_max_wait_seconds_bounds(self):
        with pytest.raises(ValidationError):
            AiAnalysisInput(file_hash=DUMMY_SHA256, max_wait_seconds=29)
        with pytest.raises(ValidationError):
            AiAnalysisInput(file_hash=DUMMY_SHA256, max_wait_seconds=3601)

    def test_no_function_addresses_or_max_functions_field(self):
        """These were power-user knobs that exposed backend implementation
        detail (PR9630 #49838/#49861). The agent-facing AI analysis tool
        always analyses the platform's default function selection."""
        self.assertNotIn("function_addresses", AiAnalysisInput.model_fields)
        self.assertNotIn("max_functions", AiAnalysisInput.model_fields)
