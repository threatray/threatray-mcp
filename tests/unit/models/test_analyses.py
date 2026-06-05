"""Tests for models/analyses.py inputs."""

import unittest
from uuid import UUID

import pytest
from hamcrest import assert_that, equal_to, instance_of, is_
from pydantic import ValidationError

from tests.dummies import DUMMY_SAMPLE_ANALYSIS_ID
from threatray_mcp.models import AnalysisIdInput, EndpointScanAnalysesListInput, Verdict


class TestAnalysisIdInput(unittest.TestCase):
    def test_valid_uuid(self):
        result = AnalysisIdInput(analysis_id=DUMMY_SAMPLE_ANALYSIS_ID)
        assert_that(result.analysis_id, is_(instance_of(UUID)))

    def test_invalid_uuid(self):
        with pytest.raises(ValidationError):
            AnalysisIdInput(analysis_id="not-a-uuid")


class TestEndpointScanAnalysesListInput(unittest.TestCase):
    def test_verdicts_filter_accepts_valid_subset(self):
        result = EndpointScanAnalysesListInput(verdicts=[Verdict.MALICIOUS])
        assert_that(result.verdicts, equal_to([Verdict.MALICIOUS]))

    def test_verdicts_filter_rejects_unknown(self):
        with pytest.raises(ValidationError):
            EndpointScanAnalysesListInput(verdicts=["malicious", "very-bad"])

    def test_limit_bounds(self):
        with pytest.raises(ValidationError):
            EndpointScanAnalysesListInput(limit=0)
        with pytest.raises(ValidationError):
            EndpointScanAnalysesListInput(limit=201)
