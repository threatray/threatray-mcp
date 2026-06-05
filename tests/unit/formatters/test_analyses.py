"""Tests for formatters/analyses.py — mocks mirror the real /v1/analyses/{id} payload."""

import unittest

from hamcrest import assert_that, contains_string, is_not

from tests.dummies import (
    DUMMY_MD5,
    DUMMY_OSINT_TITLE,
    DUMMY_OSINT_URL,
    DUMMY_SAMPLE_ANALYSIS_ID,
    DUMMY_SAMPLE_ANALYSIS_ID_B,
    DUMMY_SHA1,
    DUMMY_SHA256,
    DUMMY_SHA256_B,
    DUMMY_SHA256_C,
)
from threatray_mcp.formatters import (
    format_analyses_list,
    format_analysis_details,
    format_endpoint_scan_analyses,
    format_osint_report,
)
from threatray_mcp.formatters.analyses import osint_reports_overflow


def _analysis_payload():
    """Trimmed copy of the /v1/analyses/{id} response shape from a malicious
    AutoHotkey-wrapper sample. Keeps the structural fields we render."""
    return {
        "sample": {
            "hash_sha256": DUMMY_SHA256,
            "hash_sha1": DUMMY_SHA1,
            "hash_md5": DUMMY_MD5,
            "file_name": "Ahk2Exe.exe",
            "file_type": "Exe (PE, x86-32)",
            "file_size": 995328,
            "first_seen": {"source": "1777557616.0", "parsedValue": 1777557616},
            "magic": "PE32 executable (GUI) Intel 80386",
            "verdict": "malicious",
            "threats": [{"label": "ADMINTOOL_AutoHotkey", "confidence": "high", "scope": "public"}],
            "scope": "private",
            "static_analysis": {
                "function_count": 1542,
                "function_counts": {
                    "unknown_function_count": 233,
                    "malicious_function_count": 858,
                    "benign_function_count": 387,
                    "generic_benign_function_count": 64,
                },
                "code_detections": [
                    {
                        "verdict": "malicious",
                        "score": 0.7653880464,
                        "overlap": 858,
                        "code_signature": {"id": 1559, "name": "ADMINTOOL_AutoHotkey"},
                        "family": {"id": 4375, "name": "ADMINTOOL_AutoHotkey", "category": "malware"},
                    },
                    {
                        "verdict": "benign",
                        "score": {"source": "1.0", "parsedValue": 1},
                        "overlap": 340,
                        "code_signature": {"id": 3719, "name": "MSVC2010 (10.0)"},
                        "family": {"id": 330513, "name": "MSVC", "category": "runtime"},
                    },
                ],
            },
        },
        "analysis": {
            "id": DUMMY_SAMPLE_ANALYSIS_ID,
            "creation_time": 1777557617,
            "environment": "win10_latest_x64",
            "type": "dynamic",
            "analysis_time": 180,
            "analysis_timeout": 180,
            "verdict": "malicious",
            "scope": "private",
            "threats": [{"label": "ADMINTOOL_AutoHotkey", "confidence": "high"}],
            "verdict_details": {
                "av": [{"verdict": "unknown", "threat": ""}],
                "yara": None,
                "code": [
                    {
                        "name": "ADMINTOOL_AutoHotkey",
                        "family": {"name": "ADMINTOOL_AutoHotkey", "category": "malware"},
                        "verdict": "malicious",
                    }
                ],
                "behavioral_signatures": None,
            },
        },
        "processes": [
            {
                "pid": 5840,
                "ppid": 0,
                "status": "active",
                "name": "ahk2exe.exe",
                "command_line": '"c:\\users\\<USERNAME>\\desktop\\ahk2exe.exe"',
                "verdict": "malicious",
                "threats": [{"label": "ADMINTOOL_AutoHotkey", "confidence": "high"}],
                "memory_regions": [
                    {
                        "base": 4194304,
                        "size": 1036288,
                        "type": "Main Image",
                        "image": "c:\\users\\<USERNAME>\\desktop\\ahk2exe.exe",
                        "hash_sha256": DUMMY_SHA256_B,
                        "verdict": "malicious",
                        "code_detections": [
                            {
                                "verdict": "malicious",
                                "score": 0.7653880464,
                                "overlap": 858,
                                "code_signature": {"name": "ADMINTOOL_AutoHotkey"},
                                "family": {"name": "ADMINTOOL_AutoHotkey", "category": "malware"},
                            },
                        ],
                    },
                ],
            },
            {
                "pid": 5780,
                "ppid": 5840,
                "status": "terminated",
                "name": "cmd.exe",
                "command_line": '"c:\\windows\\system32\\cmd.exe" /c echo 1',
                "verdict": "unknown",
                "memory_regions": [],
            },
        ],
        "ioc": {
            "domains": [],
            "ips": [],
            "urls": [],
            "files": [
                {
                    "filename": "c:\\users\\<USERNAME>\\desktop\\ahk2exe.exe",
                    "operations": ["access", "read"],
                },
            ],
            "mutexes": [
                {"mutex": "ZonesCounterMutex"},
                {"mutex": "5-84N66T919IVzXY"},
            ],
            "registry": [
                {
                    "registry_key": "HKEY_CURRENT_USER\\Software\\AutoHotkey\\Ahk2Exe",
                    "operations": ["access"],
                },
            ],
        },
    }


class TestFormatAnalysisDetails(unittest.TestCase):
    def test_renders_sample_and_analysis_overview(self):
        result = format_analysis_details(_analysis_payload())
        assert_that(result, contains_string("Ahk2Exe.exe"))
        assert_that(result, contains_string("malicious"))
        assert_that(result, contains_string("Exe (PE, x86-32), 995328 bytes"))
        assert_that(result, contains_string("win10_latest_x64"))
        assert_that(result, contains_string("dynamic"))
        # creation_time = 1777557617 (Unix epoch) renders as `YYYY-MM-DD HH:MM:SS UTC`.
        assert_that(result, contains_string("2026-04-30 14:00:17 UTC"))

    def test_renders_verdict_details_engines(self):
        result = format_analysis_details(_analysis_payload())
        assert_that(result, contains_string("Verdict breakdown"))
        assert_that(result, contains_string("code: ADMINTOOL_AutoHotkey"))

    def test_renders_static_analysis_function_counts(self):
        result = format_analysis_details(_analysis_payload())
        assert_that(result, contains_string("Static analysis (1542 functions)"))
        assert_that(result, contains_string("858 malicious"))
        assert_that(result, contains_string("233 unknown"))
        # benign + generic_benign flattened (387 + 64 = 451) to mirror the UI.
        assert_that(result, contains_string("451 benign"))

    def test_renders_code_detections_as_three_column_table(self):
        result = format_analysis_details(_analysis_payload())
        # Code detections render as a three-column markdown table:
        # Label · Category · Overlap. No verdict, no score column (UI rule).
        assert_that(result, contains_string("Code detections"))
        assert_that(result, contains_string("| Label | Category | Overlap |"))
        assert_that(result, contains_string("`ADMINTOOL_AutoHotkey`"))
        assert_that(result, contains_string("`MSVC`"))
        # MSVC has category 'runtime' in fixture — column cell, not parenthesized.
        assert_that(result, contains_string("| `MSVC` | runtime |"))

    def test_code_detections_table_renders_overlap_absolute_and_relative(self):
        """Overlap cell renders as `<abs> (<percent>%)` when total function
        count is available, mirroring the UI's Code Intelligence tab."""
        result = format_analysis_details(_analysis_payload())
        # ADMINTOOL_AutoHotkey overlap=858 against function_count=1542 → 55.6%.
        assert_that(result, contains_string("| 858 (55.6%) |"))
        # MSVC overlap=340 against 1542 → 22.0%.
        assert_that(result, contains_string("| 340 (22.0%) |"))

    def test_code_detections_table_sorts_non_benign_first(self):
        """UI-style sort: malware-category families first (regardless of
        overlap), then other non-benign categories, then benign last —
        each tier ordered by overlap desc."""
        result = format_analysis_details(_analysis_payload())
        admintool_idx = result.index("`ADMINTOOL_AutoHotkey`")
        msvc_idx = result.index("`MSVC`")
        # ADMINTOOL_AutoHotkey is malware-category; MSVC is benign — malware first.
        self.assertLess(admintool_idx, msvc_idx)

    def test_code_detections_malware_category_outranks_higher_overlap_runtime(self):
        """A malware family with overlap 6 must render BEFORE a runtime with
        overlap 322 — overlap doesn't beat category. This was the EDDIESTEALER
        vs MSVC case the UI gets right but the analyses formatter previously
        got wrong."""
        payload = _analysis_payload()
        payload["sample"]["static_analysis"]["code_detections"] = [
            # Runtime, high overlap, unknown verdict — would win under the
            # old (non-benign-first, overlap-desc) sort.
            {
                "verdict": "unknown",
                "overlap": 322,
                "family": {"name": "MSVC", "category": "runtime"},
            },
            # Malware, low overlap, malicious verdict — must come first.
            {
                "verdict": "malicious",
                "overlap": 6,
                "family": {"name": "EDDIESTEALER", "category": "malware"},
            },
        ]
        # Drop verdict_details to avoid summary-block interference.
        payload["analysis"]["verdict_details"]["code"] = []
        result = format_analysis_details(payload)
        eddie_idx = result.index("`EDDIESTEALER`")
        msvc_idx = result.index("`MSVC`")
        self.assertLess(eddie_idx, msvc_idx)

    def test_renders_processes_with_command_lines(self):
        result = format_analysis_details(_analysis_payload())
        assert_that(result, contains_string("PID 5840 (parent 0): `ahk2exe.exe`"))
        assert_that(result, contains_string("Command line"))
        assert_that(result, contains_string("ahk2exe.exe"))

    def test_renders_memory_regions_with_per_region_detections(self):
        result = format_analysis_details(_analysis_payload())
        assert_that(result, contains_string("**Memory regions** (1)"))
        assert_that(result, contains_string("Main Image"))
        assert_that(result, contains_string("0x400000"))
        assert_that(result, contains_string("code_detections (1)"))

    def test_renders_iocs_with_operations(self):
        result = format_analysis_details(_analysis_payload())
        assert_that(result, contains_string("Files (1)"))
        assert_that(result, contains_string("ahk2exe.exe"))
        assert_that(result, contains_string("access, read"))
        assert_that(result, contains_string("Registry (1)"))
        assert_that(result, contains_string("AutoHotkey\\Ahk2Exe"))

    def test_renders_mutex_values_not_dict_repr(self):
        result = format_analysis_details(_analysis_payload())
        assert_that(result, contains_string("Mutexes (2)"))
        # The mutex value renders verbatim; the dict wrapper {"mutex": ...} is
        # unwrapped (regression guard against the previous str(dict) output).
        assert_that(result, contains_string("`ZonesCounterMutex`"))
        assert_that(result, contains_string("`5-84N66T919IVzXY`"))
        self.assertNotIn("'mutex':", result)
        self.assertNotIn("{'mutex'", result)

    def test_minimal_payload(self):
        result = format_analysis_details({"analysis": {"id": "a-1", "verdict": "unknown"}, "sample": {}})
        assert_that(result, contains_string("`a-1`"))
        assert_that(result, contains_string("Verdict"))


class TestFormatOsintReport(unittest.TestCase):
    def test_empty_reports(self):
        result = format_osint_report({"osint": []})
        assert_that(result, contains_string("0 similar samples from 0 threat report(s)"))

    def test_pivots_to_sample_first_grouping(self):
        """Sample-first layout matching the UI's samples-reports table.
        One sample mentioned in one report — sample header carries verdict
        + threats (no confidence suffix), report nests beneath as a single
        bullet."""
        data = {
            "osint": [
                {
                    "url": DUMMY_OSINT_URL,
                    "code_regions": [
                        {
                            "analysis_id": DUMMY_SAMPLE_ANALYSIS_ID_B,
                            "sample_hash_sha256": DUMMY_SHA256_C,
                            "code_region_hash": "r" * 64,
                            "verdict": "malicious",
                            "threats": [{"label": "ADMINTOOL_AutoHotkey", "confidence": "high"}],
                            "score": {"source": "1.0", "parsedValue": 1},
                        }
                    ],
                    "extracted_data": {
                        "url": DUMMY_OSINT_URL,
                        "title": DUMMY_OSINT_TITLE,
                        "publication_date": None,
                    },
                }
            ]
        }
        result = format_osint_report(data)
        assert_that(result, contains_string("1 similar samples from 1 threat report(s)"))
        # Confidence dropped globally — threats render as bare labels.
        assert_that(result, contains_string("malicious, threats: ADMINTOOL_AutoHotkey"))
        self.assertNotIn("(high)", result)
        # New label "Threat reports (N)" replaces "Mentioned in N report(s)".
        assert_that(result, contains_string("Threat reports (1)"))
        assert_that(result, contains_string(DUMMY_OSINT_TITLE))
        assert_that(result, contains_string(DUMMY_OSINT_URL))
        # Code match line uses bare integer percent (no "% (code similarity)").
        assert_that(result, contains_string("100%"))
        self.assertNotIn("(code similarity)", result)

    def test_report_dedupe_by_identity(self):
        """A single report referencing the same sample via multiple
        code-regions appears ONCE in the per-sample report list — matches
        UI's `!entries.includes(entry)` dedupe. Previously the formatter
        appended one row per (report, code_region), so a report with 3
        regions for the same sample showed up 3 times."""
        sample = "c" * 64
        data = {
            "osint": [
                {
                    "url": "https://a.example/report-1",
                    "code_regions": [
                        # Same report, same sample, three different regions
                        # → one bullet in the rendered list, not three.
                        {"sample_hash_sha256": sample, "verdict": "malicious",
                         "score": 1.0, "code_region_hash": "r1"},
                        {"sample_hash_sha256": sample, "verdict": "malicious",
                         "score": 0.6, "code_region_hash": "r2"},
                        {"sample_hash_sha256": sample, "verdict": "malicious",
                         "score": 0.3, "code_region_hash": "r3"},
                    ],
                    "extracted_data": {
                        "title": "Single Report",
                        "url": "https://a.example/report-1",
                        "publication_date": "2026-02-14T10:00:00",
                    },
                },
            ]
        }
        result = format_osint_report(data)
        # One report, one count, one occurrence in the rendered list.
        assert_that(result, contains_string("Threat reports (1)"))
        self.assertEqual(result.count("Single Report"), 1)
        # Best code match = the highest-scoring region (r1 at 100%).
        assert_that(result, contains_string("`r1` · 100%"))

    def test_one_sample_mentioned_in_two_reports_aggregates(self):
        """A sample mentioned in two distinct reports collapses into one
        sample section with both reports listed. Best-score aggregation
        picks the higher per-region score for the Code match line."""
        sample = "c" * 64
        data = {
            "osint": [
                {
                    "url": "https://a.example/report-1",
                    "code_regions": [
                        {"sample_hash_sha256": sample, "verdict": "malicious",
                         "threats": [{"label": "Lumma", "confidence": "high"}],
                         "score": 0.85, "code_region_hash": "ra"},
                    ],
                    "extracted_data": {
                        "title": "Report A",
                        "url": "https://a.example/report-1",
                        "publication_date": "2026-02-14T10:00:00",
                    },
                },
                {
                    "url": "https://b.example/report-2",
                    "code_regions": [
                        {"sample_hash_sha256": sample, "verdict": "malicious",
                         "threats": [{"label": "Lumma", "confidence": "high"}],
                         "score": 0.92, "code_region_hash": "rb"},
                    ],
                    "extracted_data": {
                        "title": "Report B",
                        "url": "https://b.example/report-2",
                        "publication_date": "2026-03-01T12:00:00",
                    },
                },
            ]
        }
        result = format_osint_report(data)
        assert_that(result, contains_string("1 similar samples from 2 threat report(s)"))
        # Best code match = 92% from Report B's region (highest score).
        assert_that(result, contains_string("`rb` · 92%"))
        # Two reports listed under this sample.
        assert_that(result, contains_string("Threat reports (2)"))
        assert_that(result, contains_string("Report A"))
        assert_that(result, contains_string("Report B"))
        # Report B (newer pub_date 2026-03-01) sorts before Report A (2026-02-14).
        self.assertLess(result.index("Report B"), result.index("Report A"))

    def test_hash_equal_renders_as_this_sample_literal(self):
        """`sample_is_hash_equal=True` on a code-region means THAT matched
        sample IS the queried hash. The UI renders this as the literal
        text `This sample` (no region hash, no percentage); the markdown
        view follows. A co-mentioned similar sample (without the flag)
        renders as `<region_hash> · <P>%` instead."""
        data = {
            "osint": [
                {
                    "url": "https://x.example",
                    "code_regions": [
                        {
                            "sample_hash_sha256": "qu" * 32,
                            "sample_is_hash_equal": True,
                            "verdict": "malicious",
                            "score": 1.0,
                            "code_region_hash": "rqu",
                        },
                        {
                            "sample_hash_sha256": "si" * 32,
                            "sample_is_hash_equal": False,
                            "verdict": "malicious",
                            "score": 0.4,
                            "code_region_hash": "rsi",
                        },
                    ],
                    "extracted_data": {
                        "title": DUMMY_OSINT_TITLE,
                        "url": "https://x.example",
                        "publication_date": None,
                    },
                }
            ]
        }
        result = format_osint_report(data)
        # Queried sample (sample_is_hash_equal=True) tops the list — UI rule.
        qu_idx = result.index("quququ")
        si_idx = result.index("sisisi")
        self.assertLess(qu_idx, si_idx)
        # Its Code match line is the literal "This sample (hash-equal)".
        qu_block = result[qu_idx:si_idx]
        self.assertIn("Code match**: This sample (hash-equal)", qu_block)
        # The similar sample's Code match shows region + percent — no
        # "(code similarity)" suffix, no "(hash-equal)" suffix.
        si_block = result[si_idx:]
        self.assertIn("`rsi` · 40%", si_block)
        self.assertNotIn("hash-equal", si_block)

    def test_samples_sorted_hash_equal_first_then_score_desc(self):
        """Multiple samples — queried sample (hash-equal sentinel) at the
        top, then by best code-region score desc. Matches the UI's
        `sample_is_hash_equal ? 101 : code_region.score` sort key."""
        data = {
            "osint": [
                {
                    "url": "https://x.example",
                    "code_regions": [
                        {"sample_hash_sha256": "lo" * 32, "verdict": "malicious", "score": 0.5},
                        {"sample_hash_sha256": "hi" * 32, "verdict": "suspicious", "score": 0.95},
                        {"sample_hash_sha256": "md" * 32, "verdict": "malicious", "score": 0.7},
                        # The queried sample — wins the sort regardless of score.
                        {"sample_hash_sha256": "qq" * 32, "verdict": "malicious",
                         "sample_is_hash_equal": True, "score": 0.1},
                    ],
                    "extracted_data": {
                        "title": DUMMY_OSINT_TITLE,
                        "url": "https://x.example",
                        "publication_date": None,
                    },
                }
            ]
        }
        result = format_osint_report(data)
        qq_idx = result.index("qqqqqq")
        hi_idx = result.index("hihihi")
        md_idx = result.index("mdmdmd")
        lo_idx = result.index("lolo")
        # Hash-equal first regardless of its score (0.1 here).
        self.assertLess(qq_idx, hi_idx)
        self.assertLess(hi_idx, md_idx)
        self.assertLess(md_idx, lo_idx)

    def test_low_grade_domains_sort_to_bottom_of_each_sample(self):
        """UI rule: reports from LOW_GRADE_DOMAINS sort after every other
        report, regardless of publication date. `alienvault.com` is one
        such domain; an elastic.co report with an older date still
        outranks it."""
        sample = "c" * 64
        data = {
            "osint": [
                {
                    "url": "https://otx.alienvault.com/pulse/123",
                    "code_regions": [
                        {"sample_hash_sha256": sample, "verdict": "malicious",
                         "score": 0.5, "code_region_hash": "r1"},
                    ],
                    "extracted_data": {
                        "title": "AlienVault Pulse",
                        "url": "https://otx.alienvault.com/pulse/123",
                        "publication_date": "2026-12-01T00:00:00",
                    },
                },
                {
                    "url": "https://www.elastic.co/security-labs/eddiestealer",
                    "code_regions": [
                        {"sample_hash_sha256": sample, "verdict": "malicious",
                         "score": 0.5, "code_region_hash": "r1"},
                    ],
                    "extracted_data": {
                        "title": "Elastic Labs Writeup",
                        "url": "https://www.elastic.co/security-labs/eddiestealer",
                        "publication_date": "2025-05-30T00:00:00",
                    },
                },
            ]
        }
        result = format_osint_report(data)
        # Elastic before AlienVault even though AlienVault's date is newer.
        self.assertLess(result.index("Elastic Labs Writeup"), result.index("AlienVault Pulse"))

    def test_per_sample_cap_truncates_long_report_list(self):
        """Default cap of 5 — a sample with 8 reports renders 5 + `… and 3 more`."""
        sha = "a" * 64
        data = {
            "osint": [
                {
                    "url": f"https://example/report-{i}",
                    "code_regions": [
                        {"sample_hash_sha256": sha, "score": 0.5, "code_region_hash": "r1"}
                    ],
                    "extracted_data": {
                        "title": f"Report {i:02d}",
                        "url": f"https://example/report-{i}",
                        "publication_date": "2026-01-01T00:00:00",
                    },
                }
                for i in range(8)
            ]
        }
        result = format_osint_report(data)
        # 5 of 8 inline, then a footer.
        for i in range(5):
            assert_that(result, contains_string(f"Report 0{i}"))
        assert_that(result, contains_string("… and 3 more report(s)"))

    def test_per_sample_cap_disabled_renders_every_report(self):
        """`max_reports_per_sample=None` is the spill-to-disk path's contract:
        every report renders, no `… and N more` footer."""
        sha = "a" * 64
        data = {
            "osint": [
                {
                    "url": f"https://example/report-{i}",
                    "code_regions": [
                        {"sample_hash_sha256": sha, "score": 0.5, "code_region_hash": "r1"}
                    ],
                    "extracted_data": {
                        "title": f"Report {i:02d}",
                        "url": f"https://example/report-{i}",
                        "publication_date": "2026-01-01T00:00:00",
                    },
                }
                for i in range(8)
            ]
        }
        result = format_osint_report(data, max_reports_per_sample=None)
        for i in range(8):
            assert_that(result, contains_string(f"Report 0{i}"))
        assert_that(result, is_not(contains_string("… and")))


class TestOsintReportsOverflow(unittest.TestCase):
    def test_returns_true_when_any_sample_exceeds_cap(self):
        sha = "a" * 64
        data = {
            "osint": [
                {"code_regions": [{"sample_hash_sha256": sha, "score": 0.5}]}
                for _ in range(6)  # one sample x 6 reports -> trips the 5-cap
            ]
        }
        assert osint_reports_overflow(data) is True

    def test_returns_false_when_all_samples_under_cap(self):
        sha = "a" * 64
        data = {
            "osint": [
                {"code_regions": [{"sample_hash_sha256": sha, "score": 0.5}]}
                for _ in range(5)  # exactly at the cap, no overflow
            ]
        }
        assert osint_reports_overflow(data) is False

    def test_returns_false_on_empty(self):
        assert osint_reports_overflow({"osint": []}) is False

    def test_counts_distinct_reports_not_code_regions(self):
        """One report with 10 code-regions for the same sample is still
        ONE report — overflow should be False even though the raw
        code-region count is well above the cap. Matches the UI's
        dedupe-by-report-identity rule."""
        sha = "a" * 64
        data = {
            "osint": [
                {
                    # 10 code_regions, same sample, same report → dedupes to 1.
                    "code_regions": [
                        {"sample_hash_sha256": sha, "score": 0.5}
                        for _ in range(10)
                    ]
                }
            ]
        }
        assert osint_reports_overflow(data) is False


class TestFormatEndpointScanAnalyses(unittest.TestCase):
    def test_hostname_extracted(self):
        data = {
            "analyses": [
                {
                    "id": "a1",
                    "endpoint": {"host_name": "host-01"},
                    "analysis_finished": "2026-01-01T00:00:00",
                    "verdict": "suspicious",
                    "threats": [],
                }
            ],
            "cursor": None,
        }
        result = format_endpoint_scan_analyses(data)
        assert_that(result, contains_string("host-01"))
        assert_that(result, contains_string("suspicious"))


class TestFormatAnalysesList(unittest.TestCase):
    def test_empty_with_no_cursor(self):
        result = format_analyses_list({"analyses": [], "cursor": None})
        assert_that(result, contains_string("0 entries"))
        assert_that(result, contains_string("No more results"))

    def test_renders_sample_column_and_cursor(self):
        data = {
            "analyses": [
                {
                    "id": "a1",
                    "sample_sha256": DUMMY_SHA256,
                    "analysis_type": "dynamic",
                    "analysis_finished": "2026-01-01T00:00:00",
                    "verdict": "malicious",
                    "threats": [{"label": "Emotet", "confidence": "high"}],
                }
            ],
            "cursor": "next-page-token",
        }
        result = format_analyses_list(data)
        assert_that(result, contains_string(DUMMY_SHA256))
        assert_that(result, contains_string("dynamic"))
        assert_that(result, contains_string("malicious"))
        assert_that(result, contains_string("Emotet"))
        assert_that(result, contains_string("`next-page-token`"))
