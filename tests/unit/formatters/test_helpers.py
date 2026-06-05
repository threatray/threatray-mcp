"""Tests for the shared formatter helpers in formatters/_helpers.py."""

import unittest

from hamcrest import assert_that, equal_to

from threatray_mcp.formatters._helpers import format_timestamp


class TestFormatTimestamp(unittest.TestCase):
    def test_unix_epoch_int_renders_with_seconds_and_utc_suffix(self):
        # 1777557617 → 2026-04-30 14:00:17 UTC
        assert_that(format_timestamp(1777557617), equal_to("2026-04-30 14:00:17 UTC"))

    def test_unix_epoch_float_truncated_to_seconds(self):
        assert_that(format_timestamp(1777557617.123), equal_to("2026-04-30 14:00:17 UTC"))

    def test_date_only_mode_returns_yyyymmdd(self):
        assert_that(format_timestamp(1777557617, date_only=True), equal_to("2026-04-30"))

    def test_iso_string_re_emits_in_uniform_utc_form(self):
        # ISO inputs are re-formatted into the same `YYYY-MM-DD HH:MM:SS UTC`
        # form as epoch inputs, so every tool's full-datetime is uniform.
        assert_that(
            format_timestamp("2026-05-20T09:55:06.352971Z"),
            equal_to("2026-05-20 09:55:06 UTC"),
        )
        assert_that(
            format_timestamp("2026-05-20T09:55:06+00:00"),
            equal_to("2026-05-20 09:55:06 UTC"),
        )
        # Naive ISO strings (no zone) are treated as UTC.
        assert_that(
            format_timestamp("2026-05-20T09:55:06"),
            equal_to("2026-05-20 09:55:06 UTC"),
        )

    def test_iso_string_date_only_returns_first_ten_chars(self):
        assert_that(
            format_timestamp("2026-05-20T09:55:06.352971Z", date_only=True),
            equal_to("2026-05-20"),
        )

    def test_dict_wrapper_recurses_into_parsedvalue(self):
        # The API wraps numeric fields it can't represent natively as
        # {source, parsedValue}; the helper recurses on the inner value.
        assert_that(
            format_timestamp({"source": "1777557617.0", "parsedValue": 1777557617}),
            equal_to("2026-04-30 14:00:17 UTC"),
        )

    def test_none_and_empty_string_render_as_dash(self):
        assert_that(format_timestamp(None), equal_to("-"))
        assert_that(format_timestamp(""), equal_to("-"))

    def test_unparseable_int_falls_back_to_str(self):
        # Way out of `datetime.fromtimestamp` range → fall back rather than raise.
        huge = 10**18
        assert_that(format_timestamp(huge), equal_to(str(huge)))
