"""Verifies the typed exception hierarchy carries the message + status code."""

import unittest

from hamcrest import assert_that, equal_to

from threatray_mcp.errors import ThreatrayNotFound


class TestThreatrayError(unittest.TestCase):
    def test_error_carries_message_and_status(self):
        err = ThreatrayNotFound("missing", 404)
        assert_that(err.message, equal_to("missing"))
        assert_that(err.status_code, equal_to(404))
        assert_that(str(err), equal_to("missing"))
