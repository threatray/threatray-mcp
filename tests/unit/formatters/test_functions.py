"""Tests for formatters/functions.py — mocks mirror the real /v1/functions/* shapes."""

import unittest

from hamcrest import assert_that, contains_string, not_

from tests.dummies import DUMMY_SAMPLE_ANALYSIS_ID, DUMMY_SHA256
from threatray_mcp.formatters import (
    format_code_detections,
    format_function_diff,
    format_function_retrohunt,
    format_functions_list,
)


class TestFormatFunctionsList(unittest.TestCase):
    """Real /v1/functions/{hash} payload: {"functions": [Function]} where Function
    carries address, size, uid, plus disassembly hints (api_calls, constants)."""

    def test_empty(self):
        result = format_functions_list({"functions": []})
        assert_that(result, contains_string("0 extracted"))

    def test_renders_full_columns_with_disassembly_info(self):
        """Live shape: size/api_calls/constants live under `disassembly_info`."""
        data = {
            "functions": [
                {
                    "address": 0x401000,
                    "uid": "CFF.6490927083070388341",
                    "disassembly_info": {
                        "size": 64,
                        "api_calls": ["CreateFileW", "WriteFile"],
                        "constants": [0xDEADBEEF, "user32.dll"],
                    },
                }
            ]
        }
        result = format_functions_list(data)
        assert_that(result, contains_string("API Calls"))
        assert_that(result, contains_string("Constants"))
        assert_that(result, contains_string("0x00401000"))
        assert_that(result, contains_string("CFF.6490927083070388341"))
        assert_that(result, contains_string("CreateFileW"))
        assert_that(result, contains_string("user32.dll"))
        assert_that(result, contains_string("| 64 |"))

    def test_falls_back_to_top_level_keys(self):
        """Older payloads (or test mocks) put size/api_calls/constants at the top
        level — the renderer should still pick them up."""
        data = {
            "functions": [
                {
                    "address": 0x401000,
                    "size": 64,
                    "uid": "CFF.123",
                    "api_calls": ["CreateFileW"],
                    "constants": ["user32.dll"],
                }
            ]
        }
        result = format_functions_list(data)
        assert_that(result, contains_string("CreateFileW"))
        assert_that(result, contains_string("user32.dll"))

    def test_no_metadata_renders_dash(self):
        data = {"functions": [{"address": 0x401000, "uid": "fn-1"}]}
        result = format_functions_list(data)
        assert_that(result, contains_string("| `0x00401000` | - | `fn-1` | - | - |"))


class TestFormatCodeDetections(unittest.TestCase):
    """Real /v1/functions/code-detections shape: a top-level
    {"functions": [...]} wrapper. Each function row carries analysis_id,
    code_region, pid, base, uid, address, verdict, plus an embedded code_detections
    list with the actual signature matches."""

    def test_empty(self):
        result = format_code_detections({"functions": []})
        assert_that(result, contains_string("No code detections"))

    def test_null_family_and_null_signature_detection_labelled_generic_benign(self):
        """Wire-shape note: a code-detection where BOTH `family` and
        `code_signature` are null is the UI's `Generic benign` bucket
        (typically benign verdict, score 1.0, overlap 1.0). Before the fix
        the formatter labelled these `Unknown`; now they share the same
        `Generic benign` label the analyses formatter uses, so the two views
        stay in sync."""
        data = {
            "functions": [
                # 3 functions each with a null-named detection → rolled into
                # `Generic benign`.
                {
                    "uid": f"EFF.{i}",
                    "address": 0x1000 + i,
                    "verdict": "benign",
                    "code_detections": [
                        {
                            "verdict": "benign",
                            "score": 1.0,
                            "overlap": 1.0,
                            "code_signature": None,
                            "family": None,
                            "confidence": "medium",
                            "similarity": "high",
                        }
                    ],
                }
                for i in range(3)
            ] + [
                # One real EDDIESTEALER detection to keep the summary non-trivial.
                {
                    "uid": "CFF.99",
                    "address": 0x4000,
                    "verdict": "malicious",
                    "code_detections": [
                        {
                            "verdict": "malicious",
                            "code_signature": {"name": "EDDIESTEALER"},
                            "family": {"name": "EDDIESTEALER", "category": "malware"},
                        }
                    ],
                },
            ]
        }
        result = format_code_detections(data)
        # 3 null-detection functions roll up under Generic benign.
        assert_that(result, contains_string("| `Generic benign` | - | 3 |"))
        # No stray `Unknown` family row for those same 3 functions.
        self.assertNotIn("| `Unknown` |", result)
        # EDDIESTEALER stays the dominant entry (malware tier).
        assert_that(result, contains_string("| `EDDIESTEALER` | malware | 1 |"))

    def test_groups_by_signature_with_family(self):
        data = {
            "functions": [
                {
                    "analysis_id": DUMMY_SAMPLE_ANALYSIS_ID,
                    "code_region": DUMMY_SHA256[:8],
                    "pid": 0,
                    "base": 0,
                    "uid": "EFF.-3328980268894329790",
                    "address": 6442455040,
                    "verdict": "benign",
                    "code_detections": [
                        {
                            "verdict": "benign",
                            "score": 1.0,
                            "code_signature": {"id": 6667, "name": "ntoskrnl"},
                            "family": {"id": 3537, "name": "ntoskrnl", "category": "application"},
                            "confidence": "low",
                            "similarity": "high",
                        }
                    ],
                },
                {
                    "uid": "EFF.-other",
                    "address": 6442455200,
                    "verdict": "benign",
                    "code_detections": [
                        {
                            "verdict": "benign",
                            "code_signature": {"name": "ntoskrnl"},
                            "family": {"name": "ntoskrnl", "category": "application"},
                            "confidence": "low",
                            "similarity": "high",
                        }
                    ],
                },
            ]
        }
        result = format_code_detections(data)
        # Detections now group by family.name; `ntoskrnl` is the family here.
        assert_that(result, contains_string("`ntoskrnl` family (2 functions)"))
        # Category surfaces in the header.
        assert_that(result, contains_string("application"))
        assert_that(result, contains_string("EFF.-3328980268894329790"))
        # Per-family rows now render as a markdown table (Function · UID ·
        # Verdict · Sig · Score · Conf · Sim).
        assert_that(result, contains_string("| Function | UID | Verdict | Sig | Score | Conf | Sim |"))
        # Sig column shows the signature name even when it equals the
        # family key (`ntoskrnl` here) — the previous "blank when equal"
        # rule conflated "no signature" with "signature literally named
        # the same as the family" and silently dropped data on malware
        # families like EDDIESTEALER where the two strings coincide.
        # Score renders for every verdict including benign.
        assert_that(
            result,
            contains_string("| `EFF.-3328980268894329790` | benign | `ntoskrnl` | 1.000 |"),
        )

    def test_max_detections_none_disables_per_family_cap(self):
        """When max_detections is None, the per-family cap must also be
        disabled so the spill file is truly complete (not capped at 30 rows
        per family)."""
        # 50 detections in one family — well above _MAX_DETECTIONS_PER_FAMILY (30).
        addresses = [0x400000 + i * 16 for i in range(50)]
        data = {
            "functions": [
                {
                    "uid": f"EFF.{i}",
                    "address": addr,
                    "verdict": "benign",
                    "code_detections": [
                        {
                            "verdict": "benign",
                            "score": 1.0,
                            "code_signature": {"name": "MSVC2022 (17.8)"},
                            "family": {"name": "MSVC", "category": "runtime"},
                            "confidence": "low",
                            "similarity": "high",
                        }
                    ],
                }
                for i, addr in enumerate(addresses)
            ]
        }
        # max_detections=None must render all 50 rows.
        result = format_code_detections(data, max_detections=None)
        for addr in addresses:
            assert_that(result, contains_string(f"0x{addr:08x}"))
        # No truncation marker.
        assert_that(result, not_(contains_string("more in `MSVC`")))

    def test_score_renders_for_every_verdict(self):
        """Every numeric score renders, no matter the verdict — matches the
        UI's per-function Code Detections table."""
        data = {
            "functions": [
                {
                    "uid": "EFF.malicious",
                    "address": 0x401000,
                    "verdict": "malicious",
                    "code_detections": [
                        {
                            "verdict": "malicious",
                            "score": 0.987,
                            "code_signature": {"name": "EDDIESTEALER_v1"},
                            "family": {"name": "EDDIESTEALER", "category": "malware"},
                            "confidence": "high",
                            "similarity": "high",
                        }
                    ],
                },
                {
                    "uid": "EFF.benign",
                    "address": 0x402000,
                    "verdict": "benign",
                    "code_detections": [
                        {
                            "verdict": "benign",
                            "score": 0.612,
                            "code_signature": {"name": "MSVC2022 (17.8)"},
                            "family": {"name": "MSVC", "category": "runtime"},
                            "confidence": "low",
                            "similarity": "high",
                        }
                    ],
                },
            ]
        }
        result = format_code_detections(data)
        # Score rendered for malicious row.
        assert_that(result, contains_string("malicious"))
        assert_that(result, contains_string("0.987"))
        # Score ALSO rendered for benign row (the change in this commit).
        assert_that(result, contains_string("0.612"))

    def test_sig_column_renders_signature_name_when_equal_to_family_key(self):
        """When a detection's `code_signature.name` happens to equal the
        family name (common for malware families like EDDIESTEALER /
        OSSProxy where each detection's signature is named after the
        family), the Sig column must still render the signature name —
        not collapse to `-`. The previous rule blanked these rows,
        silently dropping useful information."""
        data = {
            "functions": [
                {
                    "uid": "CFF.eddie",
                    "address": 0x14002af84,
                    "verdict": "malicious",
                    "code_detections": [
                        {
                            "verdict": "malicious",
                            "score": 1.0,
                            "code_signature": {"name": "EDDIESTEALER"},
                            "family": {"name": "EDDIESTEALER", "category": "malware"},
                            "confidence": "high",
                            "similarity": "high",
                        }
                    ],
                },
            ]
        }
        result = format_code_detections(data)
        # Sig column shows `EDDIESTEALER`, not `-`.
        assert_that(
            result,
            contains_string("| `CFF.eddie` | malicious | `EDDIESTEALER` | 1.000 |"),
        )


class TestFormatFunctionRetrohunt(unittest.TestCase):
    """Real /v1/retrohunt/functions shape: top-level keys are `functions[]`
    (input uids with their matches), `code_regions[]`, `samples[]`,
    `analyses[]` as lookup tables joinable by analysis_id."""

    def test_empty(self):
        result = format_function_retrohunt({"functions": []})
        assert_that(result, contains_string("0 reference function"))

    def test_joins_match_to_sample_via_analysis_id(self):
        data = {
            "functions": [
                {
                    "uid": "CFF.6490927083070388341",
                    "address": 0xe9a270,
                    "matches": [
                        {
                            "code_region": "11111111111111111111111111111111111111111111111111111111111111aa",
                            "analysis_id": "00000000-0000-0000-0000-000000000003",
                            "pid": 2308,
                            "base": 13565952,
                            "address": 19598816,
                            "uid": "CFF.-3800300172407233952",
                            "score": 0.998,
                            "confidence": "high",
                            "similarity": "high",
                        }
                    ],
                }
            ],
            "code_regions": [
                {
                    "analysis_id": "00000000-0000-0000-0000-000000000003",
                    "hash_sha256": "11111111111111111111111111111111111111111111111111111111111111aa",
                    "verdict": "malicious",
                    "threats": [{"label": "DawnLoader", "confidence": "high"}],
                    "nr_of_function_matches": 7,
                    "function_count": 142,
                }
            ],
            "samples": [
                {
                    "hash_sha256": "7777777777777777777777777777777777777777777777777777777777777777",
                    "analysis_id": "00000000-0000-0000-0000-000000000003",
                    "threats": [{"label": "DawnLoader", "confidence": "high"}],
                    "verdict": "malicious",
                }
            ],
            "analyses": [],
        }
        result = format_function_retrohunt(data)
        # Input UIDs surface in the top summary so the agent can pivot per row.
        assert_that(result, contains_string("**Input UIDs (1):** `CFF.6490927083070388341`"))
        assert_that(result, contains_string("malicious"))
        assert_that(result, contains_string("DawnLoader"))
        # Full sample SHA256 in the row's Sample hash column.
        assert_that(result, contains_string("7" * 64))
        # Code region cell: full region hash + N/M ref-UIDs.
        assert_that(result, contains_string(
            "`11111111111111111111111111111111111111111111111111111111111111aa` · 7/1 ref UIDs"
        ))
        # Matching-functions cell: ref→matched UID + matched address + score·conf·sim.
        assert_that(result, contains_string(
            "`CFF.6490927083070388341` → `CFF.-3800300172407233952` @ `0x012b0de0` · 1.00 · high · high"
        ))


class TestFormatFunctionDiff(unittest.TestCase):
    def _payload(self):
        source_sha = "a" * 64
        target_sha = "b" * 64
        return {
            "source_file": {
                "hash_sha256": source_sha,
                "verdict": "malicious",
                "threats": [{"label": "Emotet", "confidence": "high"}],
            },
            "files": [
                {
                    "hash_sha256": target_sha,
                    "verdict": "malicious",
                    "threats": [{"label": "Emotet", "confidence": "high"}],
                },
            ],
            "functions": [
                {
                    "uid": "CFF.source-1",
                    "address": 0x401000,
                    "cc": 5,
                    "size": 128,
                    "matches": [
                        {
                            "uid": "CFF.matched-1",
                            "address": 0x501000,
                            "hash_sha256": target_sha,
                            "score": 0.99,
                            "confidence": "high",
                            "similarity": "high",
                        },
                        {
                            "uid": "CFF.matched-2",
                            "address": 0x501080,
                            "hash_sha256": target_sha,
                            "score": 0.75,
                            "confidence": "medium",
                            "similarity": "medium",
                        },
                    ],
                },
                {
                    # No matches — should not appear in the flat table.
                    "uid": "CFF.source-2",
                    "address": 0x402000,
                    "matches": [],
                },
            ],
        }

    def test_empty(self):
        result = format_function_diff({"source_file": {}, "files": [], "functions": []})
        assert_that(result, contains_string("0 source function(s) matched"))

    def test_renders_source_metadata_block(self):
        result = format_function_diff(self._payload())
        assert_that(result, contains_string("### Source"))
        assert_that(result, contains_string(f"- **SHA256**: `{'a' * 64}`"))
        assert_that(result, contains_string("malicious"))
        assert_that(result, contains_string("Emotet"))

    def test_renders_targets_table_with_full_hashes(self):
        result = format_function_diff(self._payload())
        assert_that(result, contains_string("### Targets (1)"))
        assert_that(result, contains_string("Sample hash"))
        assert_that(result, contains_string(f"`{'b' * 64}`"))

    def test_targets_table_carries_source_fns_matched_here_not_function_count(self):
        """Per-target column is `Source fns matched here` — a count of source
        functions that found at least one match in this target. The raw
        `function_count` on the file blocks is dropped (ambiguous
        denominator — see analyses module discussion)."""
        result = format_function_diff(self._payload())
        assert_that(result, contains_string("Source fns matched here"))
        # Fixture has one source function with two matches in target B,
        # so this target's count is 1 (one distinct source function), not 2.
        assert_that(result, contains_string(f"`{'b' * 64}` | malicious | Emotet | 1 |"))
        # The header must NOT carry the dropped column.
        assert_that(result, not_(contains_string("Function count")))

    def test_match_table_carries_score_conf_sim(self):
        """Per-source-function matches are deduped by target hash (IDA-style),
        so when both fixture matches share the same target, only the
        highest-ranked one (matched-1: high confidence, 0.99) survives."""
        result = format_function_diff(self._payload())
        assert_that(result, contains_string(
            "| Source UID | Source addr | Target sample | Matched UID | Matched addr "
            "| Score | Conf | Sim |"
        ))
        # matched-1 wins the per-target dedup; matched-2 (medium conf, same
        # target) is collapsed away.
        assert_that(result, contains_string("CFF.matched-1"))
        assert_that(result, not_(contains_string("CFF.matched-2")))
        # Winning match's score rendered to two decimals.
        assert_that(result, contains_string("0.99"))

    def test_skips_source_functions_with_no_matches(self):
        result = format_function_diff(self._payload())
        # CFF.source-2 has no matches — it must NOT appear in the flat table.
        assert_that(result, not_(contains_string("CFF.source-2")))

    def test_max_matches_caps_rows_and_notes_truncation(self):
        # After IDA-style dedup the fixture has 1 match, so cap of 1 is a
        # no-op. Build a fresh payload with two distinct targets to exercise
        # the truncation path explicitly.
        source_sha = "a" * 64
        t1 = "b" * 64
        t2 = "c" * 64
        data = {
            "source_file": {"hash_sha256": source_sha, "verdict": "malicious", "threats": []},
            "files": [
                {"hash_sha256": t1, "verdict": "malicious", "threats": []},
                {"hash_sha256": t2, "verdict": "malicious", "threats": []},
            ],
            "functions": [
                {
                    "uid": "CFF.source-1",
                    "address": 0x401000,
                    "matches": [
                        {"uid": "CFF.m1", "address": 0x501000, "hash_sha256": t1,
                         "score": 0.99, "confidence": "high", "similarity": "high"},
                        {"uid": "CFF.m2", "address": 0x601000, "hash_sha256": t2,
                         "score": 0.95, "confidence": "high", "similarity": "high"},
                    ],
                }
            ],
        }
        result = format_function_diff(data, max_matches=1)
        assert_that(result, contains_string("Showing first 1 of 2 matches"))

    def test_filters_source_self_from_targets_and_matches(self):
        """The wire shape's `files[]` includes the source sample alongside
        the actual targets the caller asked for. The Targets table and the
        per-target match count must filter the source out so the output
        reflects the caller's request, not the upstream artefact."""
        source_sha = "a" * 64
        target_sha = "b" * 64
        data = {
            "source_file": {
                "hash_sha256": source_sha,
                "verdict": "malicious",
                "threats": [],
            },
            "files": [
                # Source appears here too — must be filtered.
                {"hash_sha256": source_sha, "verdict": "malicious", "threats": []},
                {"hash_sha256": target_sha, "verdict": "malicious", "threats": []},
            ],
            "functions": [
                {
                    "uid": "CFF.source-1",
                    "address": 0x401000,
                    "matches": [
                        # Self-match — must be filtered from the match table.
                        {
                            "uid": "CFF.source-1",
                            "address": 0x401000,
                            "hash_sha256": source_sha,
                            "score": 1.0,
                            "confidence": "high",
                            "similarity": "high",
                        },
                        # Real target match — must remain.
                        {
                            "uid": "CFF.target-1",
                            "address": 0x501000,
                            "hash_sha256": target_sha,
                            "score": 0.9,
                            "confidence": "high",
                            "similarity": "high",
                        },
                    ],
                }
            ],
        }
        result = format_function_diff(data)
        # Header should report 1 target, not 2.
        assert_that(result, contains_string("vs 1 target(s)"))
        # Targets table shows only the actual target row.
        assert_that(result, contains_string(f"`{target_sha}`"))
        # Total matches in the header counts only external matches (1, not 2).
        assert_that(result, contains_string("1 source function(s) matched, 1 total matches"))

    def test_ida_priority_confidence_beats_score(self):
        """The IDA plugin treats confidence as the headline signal: a
        high-confidence match at score 0.85 outranks a low-confidence match at
        score 0.99. Mirrors `_get_best_match` in the IDA function-retrohunt
        controller — score alone would give the wrong answer when the
        classifier's confidence disagrees."""
        source_sha = "a" * 64
        t1 = "b" * 64
        t2 = "c" * 64
        data = {
            "source_file": {"hash_sha256": source_sha, "verdict": "malicious", "threats": []},
            "files": [
                {"hash_sha256": t1, "verdict": "malicious", "threats": []},
                {"hash_sha256": t2, "verdict": "malicious", "threats": []},
            ],
            "functions": [
                {
                    "uid": "CFF.source-1",
                    "address": 0x401000,
                    "matches": [
                        # Low confidence, high score → should sort LAST.
                        {"uid": "CFF.low-but-high-score", "address": 0x501000,
                         "hash_sha256": t1, "score": 0.99,
                         "confidence": "low", "similarity": "low"},
                        # High confidence, modest score → should sort FIRST.
                        {"uid": "CFF.high-conf-mid-score", "address": 0x601000,
                         "hash_sha256": t2, "score": 0.85,
                         "confidence": "high", "similarity": "high"},
                    ],
                }
            ],
        }
        result = format_function_diff(data)
        hi_conf_idx = result.index("CFF.high-conf-mid-score")
        lo_conf_idx = result.index("CFF.low-but-high-score")
        self.assertLess(hi_conf_idx, lo_conf_idx)

    def test_dedupes_matches_by_target_hash(self):
        """A source function matching multiple regions of the SAME target sample
        collapses to one row per target — the IDA plugin's `_get_unique_matches`
        behaviour. Keeps the highest-ranked match (confidence-first)."""
        source_sha = "a" * 64
        target_sha = "b" * 64
        data = {
            "source_file": {"hash_sha256": source_sha, "verdict": "malicious", "threats": []},
            "files": [{"hash_sha256": target_sha, "verdict": "malicious", "threats": []}],
            "functions": [
                {
                    "uid": "CFF.source-1",
                    "address": 0x401000,
                    "matches": [
                        {"uid": "CFF.region-A", "address": 0x501000,
                         "hash_sha256": target_sha, "score": 0.80,
                         "confidence": "medium", "similarity": "medium"},
                        {"uid": "CFF.region-B", "address": 0x501100,
                         "hash_sha256": target_sha, "score": 0.95,
                         "confidence": "high", "similarity": "high"},
                        {"uid": "CFF.region-C", "address": 0x501200,
                         "hash_sha256": target_sha, "score": 0.70,
                         "confidence": "low", "similarity": "low"},
                    ],
                }
            ],
        }
        result = format_function_diff(data)
        # Only the highest-ranked region (region-B: high conf) survives.
        assert_that(result, contains_string("CFF.region-B"))
        assert_that(result, not_(contains_string("CFF.region-A")))
        assert_that(result, not_(contains_string("CFF.region-C")))
        # Header reflects post-dedup count.
        assert_that(result, contains_string("1 source function(s) matched, 1 total matches"))

    def test_outer_sort_by_prevalence_desc(self):
        """Source functions are sorted by prevalence desc — a function that
        matches three targets ranks above one that matches a single target,
        even if both have equal max scores. Mirrors the UI's `-f.prevalence`
        default sort."""
        source_sha = "a" * 64
        t1, t2, t3 = "b" * 64, "c" * 64, "d" * 64
        data = {
            "source_file": {"hash_sha256": source_sha, "verdict": "malicious", "threats": []},
            "files": [
                {"hash_sha256": t1, "verdict": "malicious", "threats": []},
                {"hash_sha256": t2, "verdict": "malicious", "threats": []},
                {"hash_sha256": t3, "verdict": "malicious", "threats": []},
            ],
            "functions": [
                {
                    # Rare function: only one target → lower prevalence,
                    # should appear AFTER the prevalent one.
                    "uid": "CFF.rare",
                    "address": 0x401000,
                    "matches": [
                        {"uid": "CFF.r1", "address": 0x501000, "hash_sha256": t1,
                         "score": 0.99, "confidence": "high", "similarity": "high"},
                    ],
                },
                {
                    # Prevalent function: three distinct targets.
                    "uid": "CFF.prevalent",
                    "address": 0x402000,
                    "matches": [
                        {"uid": "CFF.p1", "address": 0x601000, "hash_sha256": t1,
                         "score": 0.80, "confidence": "high", "similarity": "high"},
                        {"uid": "CFF.p2", "address": 0x701000, "hash_sha256": t2,
                         "score": 0.80, "confidence": "high", "similarity": "high"},
                        {"uid": "CFF.p3", "address": 0x801000, "hash_sha256": t3,
                         "score": 0.80, "confidence": "high", "similarity": "high"},
                    ],
                },
            ],
        }
        result = format_function_diff(data)
        prevalent_idx = result.index("CFF.prevalent")
        rare_idx = result.index("CFF.rare")
        self.assertLess(prevalent_idx, rare_idx)
