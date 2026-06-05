"""Tests for models/search.py inputs."""

import unittest

import pytest
from hamcrest import assert_that, equal_to
from pydantic import ValidationError

from tests.dummies import DUMMY_SHA256
from threatray_mcp.models import (
    ResponseFormat,
    RetrohuntSampleInput,
    SearchInput,
    SearchScope,
)


class TestSearchInput(unittest.TestCase):
    def test_valid_search_input(self):
        result = SearchInput(query="signature:Emotet")
        assert_that(result.query, equal_to("signature:Emotet"))
        assert_that(result.max_results, equal_to(50))
        assert_that(result.scope, equal_to(SearchScope.BOTH))
        assert_that(result.response_format, equal_to(ResponseFormat.MARKDOWN))

    def test_search_input_with_all_params(self):
        result = SearchInput(
            query="ip:192.168.1.1",
            max_results=100,
            scope=SearchScope.PRIVATE,
            date="30d",
            response_format=ResponseFormat.JSON,
        )
        assert_that(result.query, equal_to("ip:192.168.1.1"))
        assert_that(result.max_results, equal_to(100))
        assert_that(result.scope, equal_to(SearchScope.PRIVATE))
        assert_that(result.date, equal_to("30d"))
        assert_that(result.response_format, equal_to(ResponseFormat.JSON))

    def test_search_input_empty_query_rejected(self):
        with pytest.raises(ValidationError):
            SearchInput(query="")

    def test_search_input_max_results_bounds(self):
        with pytest.raises(ValidationError):
            SearchInput(query="test", max_results=0)
        with pytest.raises(ValidationError):
            SearchInput(query="test", max_results=10001)
        # 10000 — the backend hard ceiling — is accepted.
        SearchInput(query="test", max_results=10000)

    def test_search_input_strips_whitespace(self):
        result = SearchInput(query="  signature:Emotet  ")
        assert_that(result.query, equal_to("signature:Emotet"))

class TestDateValidator(unittest.TestCase):
    """Both SearchInput and RetrohuntSampleInput share the 'Nd' format."""

    def test_search_date_accepts_nd_format(self):
        assert_that(SearchInput(query="x", date="7d").date, equal_to("7d"))
        assert_that(SearchInput(query="x", date="0d").date, equal_to("0d"))
        assert_that(SearchInput(query="x", date="365d").date, equal_to("365d"))

    def test_search_date_rejects_freeform(self):
        with pytest.raises(ValidationError):
            SearchInput(query="x", date="7 days")
        with pytest.raises(ValidationError):
            SearchInput(query="x", date="2026-01-01")

    def test_retrohunt_uses_same_date_format(self):
        result = RetrohuntSampleInput(sample_hash=DUMMY_SHA256, date="30d")
        assert_that(result.date, equal_to("30d"))

    def test_retrohunt_rejects_freeform(self):
        with pytest.raises(ValidationError):
            RetrohuntSampleInput(sample_hash=DUMMY_SHA256, date="last-week")
