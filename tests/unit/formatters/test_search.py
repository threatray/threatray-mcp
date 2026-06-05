"""Tests for formatters/search.py — mocks mirror the real /v1/search payload."""

import unittest

from hamcrest import assert_that, contains_string, is_not, not_

from tests.dummies import DUMMY_SAMPLE_ANALYSIS_ID, DUMMY_SHA256
from threatray_mcp.formatters import format_retrohunt_results, format_search_results
from threatray_mcp.formatters.search import aggregations_overflow


def _search_payload():
    """Trimmed copy of the /v1/search response shape for a `file-hash:...`
    query — one analysis with verdict_details, the standard aggregation buckets."""
    return {
        "analyses": [
            {
                "id": DUMMY_SAMPLE_ANALYSIS_ID,
                "analysis_timestamp": 1777556349,
                "threats": [{"label": "NOROBOT", "confidence": "medium", "scope": "public"}],
                "verdict": "suspicious",
                "environment": "win10_latest_x64",
                "scope": "private",
                "verdict_details": {
                    "code_signatures": [{"name": "NOROBOT_2025_May"}],
                    "families": [{"name": "NOROBOT"}],
                    "av": [],
                    # Live shape uses `rule` (not `name`) for the YARA entry.
                    "yara": [{"rule": "win_norobot_a0"}],
                },
                "sample": {
                    "hash_sha256": DUMMY_SHA256,
                    "first_seen": 1777556349,
                    "file_size": 241153,
                    "file_name": "nr.exe",
                    "file_type": "DLL (PE, x86-64)",
                },
            }
        ],
        "samples": [],
        "aggregations": {
            "code_signature": [{"key": "NOROBOT_2025_May", "count": 1, "private": 1, "public": 0}],
            "family": [{"key": "NOROBOT", "count": 1, "private": 1, "public": 0}],
            "av": [],
            "mutex": [],
            "threats": [{"key": "NOROBOT", "count": 1, "private": 1, "public": 0}],
            "yara": [],
            "process": [{"key": "powershell.exe -enc ...", "count": 1}],
            "registry": [{"key": "hkey_current_user\\software\\classes\\.mollis", "count": 1}],
            "domain": [{"key": "stuseamandesilt.org", "count": 1}],
            "ip": [{"key": "91.236.230.243", "count": 1}],
            "verdict": [{"key": "suspicious", "count": 1}],
            "file": [{"key": "c:\\users\\<u>\\appdata\\local\\temp\\p1.zip", "count": 1}],
            "url": [],
        },
    }


class TestFormatSearchResults(unittest.TestCase):
    def test_empty_results(self):
        result = format_search_results({"analyses": []})
        assert_that(result, contains_string("0 analyses found"))

    def test_renders_sample_row_with_verdict_details(self):
        result = format_search_results(_search_payload())
        assert_that(result, contains_string("1 analyses found"))
        # Table columns include Scope and OSINT visibility before the verdict.
        header = (
            "| Analysis ID | Sample hash | First seen | Scope | OSINT "
            "| Verdict | Threats | YARA matches |"
        )
        assert_that(result, contains_string(header))
        assert_that(result, contains_string("suspicious"))
        assert_that(result, contains_string("NOROBOT"))
        # `first_seen` (Unix epoch 1777556349) renders as `2026-04-30`.
        assert_that(result, contains_string("2026-04-30"))
        # YARA hits collapse to a count in the rightmost column.
        assert_that(result, contains_string("| 1 |"))

    def test_scope_column_picks_up_analysis_scope(self):
        payload = _search_payload()
        payload["analyses"][0]["scope"] = "private"
        result = format_search_results(payload)
        assert_that(result, contains_string("| private |"))

    def test_osint_column_renders_yes_when_sample_osint_true(self):
        payload = _search_payload()
        payload["analyses"][0]["sample"]["osint"] = True
        result = format_search_results(payload)
        assert_that(result, contains_string("| yes |"))

    def test_osint_column_renders_no_when_sample_osint_false(self):
        payload = _search_payload()
        payload["analyses"][0]["sample"]["osint"] = False
        result = format_search_results(payload)
        assert_that(result, contains_string("| no |"))

    def test_sample_hash_column_is_full_plain_code_span(self):
        """Sample hash column renders the full SHA256 in a bare code span."""
        result = format_search_results(_search_payload())
        assert_that(result, contains_string(f"`{DUMMY_SHA256}`"))

    def test_analysis_id_column_uses_full_uuid_text(self):
        """Analysis ID cell renders the full UUID, no truncation, no link."""
        result = format_search_results(_search_payload())
        assert_that(result, contains_string(f"`{DUMMY_SAMPLE_ANALYSIS_ID}`"))
        # No truncated form anywhere in the output.
        assert_that(result, is_not(contains_string(f"`{DUMMY_SAMPLE_ANALYSIS_ID[:8]}…`")))
        # No markdown link wrapping anywhere either.
        assert_that(result, is_not(contains_string("](http")))

    def test_renders_all_aggregation_buckets(self):
        result = format_search_results(_search_payload())
        # Every non-empty aggregation bucket should appear
        assert_that(result, contains_string("Verdict distribution"))
        assert_that(result, contains_string("Threats"))
        assert_that(result, contains_string("Families"))
        assert_that(result, contains_string("Code signatures"))
        assert_that(result, contains_string("Domains"))
        assert_that(result, contains_string("IPs"))
        assert_that(result, contains_string("Files"))
        assert_that(result, contains_string("Processes"))
        assert_that(result, contains_string("Registry"))
        # And the values
        assert_that(result, contains_string("stuseamandesilt.org"))
        assert_that(result, contains_string("91.236.230.243"))

    def test_aggregation_shows_public_private_split(self):
        result = format_search_results(_search_payload())
        # The NOROBOT family row carries `private=1, public=0`
        assert_that(result, contains_string("1 private + 0 public"))

    def test_analyses_table_renders_before_statistics(self):
        """The analyses table is the analyst's primary index — it must appear
        before the aggregation buckets so the most-relevant content sits at
        the top of the response."""
        result = format_search_results(_search_payload())
        table_idx = result.index("| Analysis ID")
        stats_idx = result.index("## Statistics")
        assert table_idx < stats_idx, (
            f"Expected analyses table (idx={table_idx}) before Statistics "
            f"(idx={stats_idx}) — order is now reversed."
        )

    def test_max_samples_truncates_and_notes_footer(self):
        """When `max_samples` clips the analyses table, a `Showing first N of
        M analyses.` footer is appended — mirrors the retrohunt formatter's
        twin branch so the catalogue's `Showing first N of M` convention holds
        for search too."""
        payload = _search_payload()
        base = payload["analyses"][0]
        payload["analyses"] = [{**base, "id": f"{i:08d}-0000-0000-0000-000000000000"} for i in range(5)]
        result = format_search_results(payload, max_samples=2)
        assert_that(result, contains_string("Search Results: 5 analyses found (showing 2)"))
        assert_that(result, contains_string("*Showing first 2 of 5 analyses.*"))

    def test_no_footer_when_under_max_samples(self):
        """No truncation footer when the result fits under the cap."""
        result = format_search_results(_search_payload(), max_samples=50)
        assert_that(result, is_not(contains_string("Showing first")))

    def test_aggregation_cap_truncates_long_bucket(self):
        """Default cap of 25 — a 30-entry bucket renders 25 + a `... and 5
        more` footer."""
        payload = _search_payload()
        payload["aggregations"]["yara"] = [
            {"key": f"rule_{i:03d}", "count": 1} for i in range(30)
        ]
        result = format_search_results(payload)
        assert_that(result, contains_string("rule_000"))
        assert_that(result, contains_string("rule_024"))  # 25th, last shown
        assert_that(result, is_not(contains_string("rule_025")))  # 26th, dropped
        assert_that(result, contains_string("… and 5 more"))

    def test_aggregation_cap_disabled_renders_every_entry(self):
        """`max_aggregation_items=None` is the spill-to-disk path's contract:
        every entry in every bucket appears, no `… and N more` footer."""
        payload = _search_payload()
        payload["aggregations"]["yara"] = [
            {"key": f"rule_{i:03d}", "count": 1} for i in range(30)
        ]
        result = format_search_results(payload, max_aggregation_items=None)
        assert_that(result, contains_string("rule_000"))
        assert_that(result, contains_string("rule_029"))  # 30th, now shown
        assert_that(result, is_not(contains_string("… and")))

    def test_aggregations_overflow_returns_true_when_any_bucket_exceeds_cap(self):
        """The helper drives spill-on-overflow on the tools side. A bucket
        with 26 entries is enough to trip it."""
        payload = _search_payload()
        payload["aggregations"]["yara"] = [
            {"key": f"rule_{i:03d}", "count": 1} for i in range(26)
        ]
        assert aggregations_overflow(payload) is True

    def test_aggregations_overflow_returns_false_under_cap(self):
        # The default _search_payload's buckets all sit under the 25-entry cap.
        assert aggregations_overflow(_search_payload()) is False


def _retrohunt_payload():
    """Trimmed copy of the /v1/search response shape (with `retrohunt:<hash>`) used by
    retrohunt-by-sample. Adds the `code_regions[]` list and the per-analysis
    fields (`cr_hash_sha256`, `similarity`, `sample.function_count_in_source`)
    the retrohunt table consumes for the Code matches column."""
    payload = _search_payload()
    region_hash = "d" * 64
    payload["analyses"][0]["similarity"] = 0.47
    payload["analyses"][0]["cr_hash_sha256"] = region_hash
    payload["analyses"][0]["sample"]["function_count_in_source"] = 1114
    payload["code_regions"] = [
        {
            "hash_sha256": region_hash,
            "analysis_id": DUMMY_SAMPLE_ANALYSIS_ID,
            "function_count": 1107,
            "verdict": "malicious",
            "threats": [{"label": "NOROBOT", "confidence": "medium"}],
        }
    ]
    return payload


class TestFormatRetrohuntResults(unittest.TestCase):
    def test_renders_as_similar_samples(self):
        result = format_retrohunt_results(_search_payload())
        assert_that(result, contains_string("Similar Samples"))
        assert_that(result, contains_string("NOROBOT"))

    def test_code_matches_column_carries_full_region_and_similarity(self):
        """The retrohunt-by-sample table's Code matches column carries the
        matched code-region hash (full) and similarity %. Function counts are
        omitted — the wire shape mixes denominators."""
        result = format_retrohunt_results(_retrohunt_payload())
        header = (
            "| Analysis ID | Sample hash | First seen | Scope | OSINT "
            "| Verdict | Threats | YARA | Code matches (region · similarity) |"
        )
        assert_that(result, contains_string(header))
        # Fixture: cr_hash is 64 'd's, similarity=0.47 → 47.00% (two-decimal
        # form, so 100% remains reserved for exact-equal matches).
        assert_that(result, contains_string(f"`{'d' * 64}` · 47.00% sim"))

    def test_code_matches_column_omits_function_counts(self):
        """Function-count fragments must not appear in the Code matches cell —
        denominators are ambiguous across the wire shape."""
        result = format_retrohunt_results(_retrohunt_payload())
        assert_that(result, not_(contains_string("funcs")))
        assert_that(result, not_(contains_string("1114→1107")))

    def test_similarity_renders_at_two_decimal_unless_exact(self):
        """A retrohunt typically returns many near-identical hits; integer
        rounding made 99.99% / 99.51% / 99.04% all render as `100%` and the
        analyst couldn't tell exact-equal from very-close. Two-decimal form
        preserves the distinction; exact 1.0 still renders as `100%`."""
        payload = _retrohunt_payload()
        payload["analyses"][0]["similarity"] = 0.9994
        result = format_retrohunt_results(payload)
        assert_that(result, contains_string("99.94% sim"))
        # Now an exact match.
        payload["analyses"][0]["similarity"] = 1.0
        result = format_retrohunt_results(payload)
        assert_that(result, contains_string("100% sim"))
