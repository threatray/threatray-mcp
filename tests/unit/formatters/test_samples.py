"""Tests for formatters/samples.py.

`format_sample_details` delegates to `format_analysis_details` because
`/v1/samples/{hash}` and `/v1/analyses/{id}` return the same Analysis schema;
the underlying rendering is covered in `test_analyses.py`. Here we just check
the thin delegation contract.
"""

import unittest

from hamcrest import assert_that, contains_string

from threatray_mcp.formatters import format_sample_details


class TestFormatSampleDetails(unittest.TestCase):
    def test_delegates_to_format_analysis_details(self):
        """Smoke test — the delegation path renders the same shape as the
        analysis-details view. Full field-coverage is asserted in
        test_analyses.py."""
        data = {
            "sample": {
                "hash_sha256": "a" * 64,
                "file_name": "test.exe",
                "file_type": "PE32",
                "file_size": 1024,
                "verdict": "malicious",
                "threats": [{"label": "Emotet", "confidence": "high"}],
            },
            "analysis": {"id": "a-1", "verdict": "malicious", "type": "dynamic"},
        }
        result = format_sample_details(data)
        assert_that(result, contains_string("test.exe"))
        assert_that(result, contains_string("malicious"))
        assert_that(result, contains_string("Emotet"))
