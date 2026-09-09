"""Tests for formatters/capa.py — mocks mirror the actual CAPA payload shape."""

import unittest

from hamcrest import assert_that, contains_string, not_

from tests.dummies import DUMMY_SHA256
from threatray_mcp.formatters import format_capa_job, format_capa_job_ack, format_capa_results
from threatray_mcp.formatters.capa import capa_addresses_overflow


def _capa_payload():
    """Trimmed slice of a real CAPA payload. Real shape:
    capabilities = {meta: {sample, analysis, flavor, version}, rules: {name: {meta, matches}}}.
    Addresses come as {type: absolute, value: int}."""
    return {
        "file_hash": DUMMY_SHA256,
        "capabilities": {
            "meta": {
                "version": "9.4.0",
                "flavor": "static",
                "sample": {
                    "sha256": DUMMY_SHA256,
                },
                "analysis": {
                    "format": "pe",
                    "arch": "amd64",
                    "os": "windows",
                    "extractor": "VivisectFeatureExtractor",
                    "base_address": {"type": "absolute", "value": 6442450944},
                },
            },
            "rules": {
                "link function at runtime on Windows": {
                    "meta": {
                        "name": "link function at runtime on Windows",
                        "namespace": "linking/runtime-linking",
                        "attack": [
                            {
                                "tactic": "Execution",
                                "technique": "Shared Modules",
                                "subtechnique": "",
                                "id": "T1129",
                            }
                        ],
                        "mbc": [],
                    },
                    "matches": [
                        [{"type": "absolute", "value": 6442516739}, {}],
                        [{"type": "absolute", "value": 6442516800}, {}],
                    ],
                },
                "create process on Windows": {
                    "meta": {
                        "name": "create process on Windows",
                        "namespace": "host-interaction/process/create",
                        "attack": [],
                        "mbc": [
                            {
                                "objective": "Process",
                                "behavior": "Create Process",
                                "method": "",
                                "id": "C0017",
                            }
                        ],
                    },
                    "matches": [
                        [{"type": "absolute", "value": 6442464610}, {}],
                    ],
                },
            },
        },
    }


class TestFormatCapaResults(unittest.TestCase):
    def test_empty_capa(self):
        result = format_capa_results({"capabilities": {"meta": {}, "rules": {}}})
        assert_that(result, contains_string("No capabilities matched"))

    def test_renders_meta_block(self):
        result = format_capa_results(_capa_payload())
        assert_that(result, contains_string(DUMMY_SHA256))
        assert_that(result, contains_string("pe / amd64 / windows"))
        assert_that(result, contains_string("0x180000000"))  # base address
        assert_that(result, contains_string("CAPA version"))
        assert_that(result, contains_string("9.4.0"))

    def test_meta_block_omits_extractor_and_flavor(self):
        result = format_capa_results(_capa_payload())
        assert_that(result, not_(contains_string("Extractor")))
        assert_that(result, not_(contains_string("Flavor")))

    def test_renders_attack_inline_per_rule_not_grouped(self):
        """Mirrors the UI: no top-level grouping by ATT&CK tactic. ATT&CK
        metadata appears inline on each rule that carries it."""
        result = format_capa_results(_capa_payload())
        assert_that(result, contains_string("Capabilities"))
        assert_that(result, contains_string("link function at runtime on Windows"))
        assert_that(result, contains_string("ATT&CK: Execution / Shared Modules [T1129]"))
        assert_that(result, contains_string("linking/runtime-linking"))
        # No ATT&CK tactic grouping headers.
        assert_that(result, not_(contains_string("Capabilities by ATT&CK tactic")))

    def test_renders_match_count_and_address_samples(self):
        result = format_capa_results(_capa_payload())
        # The link-runtime rule has 2 matches → both addresses shown
        assert_that(result, contains_string("2 match(es)"))
        assert_that(result, contains_string("0x180010103"))
        assert_that(result, contains_string("0x180010140"))

    def test_renders_mbc_inline(self):
        result = format_capa_results(_capa_payload())
        # create-process has MBC but no attack — still rendered in the flat list.
        assert_that(result, contains_string("create process on Windows"))
        assert_that(result, contains_string("MBC: Process::Create Process [C0017]"))

    def test_filters_noisy_namespaces(self):
        """Rules under `internal/` or `library/` namespaces mirror the UI's
        noise filter — they're hidden, and the header notes the count."""
        payload = {
            "capabilities": {
                "meta": {},
                "rules": {
                    "library api lookup": {
                        "meta": {
                            "name": "library api lookup",
                            "namespace": "library/runtime",
                            "attack": [],
                            "mbc": [],
                        },
                        "matches": [[{"type": "absolute", "value": 0x401000}, {}]],
                    },
                    "create process on Windows": {
                        "meta": {
                            "name": "create process on Windows",
                            "namespace": "host-interaction/process/create",
                            "attack": [],
                            "mbc": [],
                        },
                        "matches": [[{"type": "absolute", "value": 0x401020}, {}]],
                    },
                },
            },
        }
        result = format_capa_results(payload)
        assert_that(result, contains_string("create process on Windows"))
        assert_that(result, contains_string("1 internal/library rules hidden"))
        assert_that(result, not_(contains_string("library api lookup")))

    def test_doesnt_leak_full_match_tree(self):
        """The match tree is enormous — we only show addresses, not the inner
        feature/statement nodes."""
        result = format_capa_results(_capa_payload())
        assert_that(result, not_(contains_string("statement")))
        assert_that(result, not_(contains_string("captures")))

    def test_emits_every_address_when_under_per_rule_cap(self):
        """Rules with ≤ the per-rule cap (30 by default) render every
        address inline, no truncation marker."""
        addresses = [0x401000 + i * 16 for i in range(10)]
        payload = {
            "capabilities": {
                "meta": {},
                "rules": {
                    "contain loop": {
                        "meta": {
                            "name": "contain loop",
                            "namespace": "",
                            "attack": [],
                            "mbc": [],
                        },
                        "matches": [[{"type": "absolute", "value": a}, {}] for a in addresses],
                    },
                },
            },
        }
        result = format_capa_results(payload)
        for a in addresses:
            assert_that(result, contains_string(f"0x{a:x}"))
        assert_that(result, not_(contains_string("more)")))

    def test_per_rule_cap_truncates_long_address_list(self):
        """A rule with > 30 addresses renders the first 30 + a
        `*(… and N more)*` footer. Mirrors the `contain loop` rule on
        EddieStealer (421 addresses) — without the cap a single rule
        used to drown out every other rule in the response."""
        addresses = [0x140001000 + i * 16 for i in range(50)]
        payload = {
            "capabilities": {
                "meta": {},
                "rules": {
                    "contain loop": {
                        "meta": {
                            "name": "contain loop",
                            "namespace": "",
                            "attack": [],
                            "mbc": [],
                        },
                        "matches": [[{"type": "absolute", "value": a}, {}] for a in addresses],
                    },
                },
            },
        }
        result = format_capa_results(payload)
        # First 30 addresses render inline.
        for a in addresses[:30]:
            assert_that(result, contains_string(f"0x{a:x}"))
        # 31st+ addresses suppressed; truncation footer instead.
        self.assertNotIn(f"0x{addresses[30]:x}", result)
        assert_that(result, contains_string("(… and 20 more)"))

    def test_max_addresses_per_rule_none_disables_cap(self):
        """`max_addresses_per_rule=None` lifts the per-rule cap — used by
        the spill-to-disk path so the cached markdown is exhaustive."""
        addresses = [0x140001000 + i * 16 for i in range(50)]
        payload = {
            "capabilities": {
                "meta": {},
                "rules": {
                    "contain loop": {
                        "meta": {"name": "contain loop", "namespace": "",
                                  "attack": [], "mbc": []},
                        "matches": [[{"type": "absolute", "value": a}, {}] for a in addresses],
                    },
                },
            },
        }
        result = format_capa_results(payload, max_addresses_per_rule=None)
        for a in addresses:
            assert_that(result, contains_string(f"0x{a:x}"))
        assert_that(result, not_(contains_string("more)")))

    def test_renders_no_address_marker(self):
        """File-level CAPA matches have `{type: 'no address'}` instead of a real
        offset — should render as `n/a`, not the raw dict."""
        payload = {
            "capabilities": {
                "meta": {},
                "rules": {
                    "contain an embedded PE file": {
                        "meta": {
                            "name": "contain an embedded PE file",
                            "namespace": "executable/subfile/pe",
                            "attack": [],
                            "mbc": [],
                        },
                        "matches": [[{"type": "no address"}, {}]],
                    },
                },
            },
        }
        result = format_capa_results(payload)
        assert_that(result, contains_string("n/a"))
        assert_that(result, not_(contains_string("'type': 'no address'")))


class TestCapaAddressesOverflow(unittest.TestCase):
    def test_returns_true_when_any_rule_exceeds_cap(self):
        # 50 addresses on `contain loop` → > 30 cap → overflow.
        payload = {
            "capabilities": {
                "meta": {},
                "rules": {
                    "contain loop": {
                        "meta": {"name": "contain loop", "namespace": ""},
                        "matches": [
                            [{"type": "absolute", "value": 0x140001000 + i * 16}, {}]
                            for i in range(50)
                        ],
                    },
                },
            },
        }
        assert capa_addresses_overflow(payload) is True

    def test_returns_false_when_all_rules_under_cap(self):
        payload = {
            "capabilities": {
                "meta": {},
                "rules": {
                    "encode data using XOR": {
                        "meta": {"name": "encode data using XOR", "namespace": ""},
                        "matches": [
                            [{"type": "absolute", "value": 0x140001000 + i * 16}, {}]
                            for i in range(5)
                        ],
                    },
                },
            },
        }
        assert capa_addresses_overflow(payload) is False

    def test_ignores_noisy_namespaces(self):
        """A rule with 100 addresses under `internal/` shouldn't count —
        those rules are filtered out of the rendered output anyway, so
        their address count doesn't drive the spill decision."""
        payload = {
            "capabilities": {
                "meta": {},
                "rules": {
                    "internal noise": {
                        "meta": {"name": "internal noise", "namespace": "internal/foo"},
                        "matches": [
                            [{"type": "absolute", "value": 0x140001000 + i * 16}, {}]
                            for i in range(100)
                        ],
                    },
                },
            },
        }
        assert capa_addresses_overflow(payload) is False

    def test_returns_false_on_empty(self):
        assert capa_addresses_overflow({}) is False
        assert capa_addresses_overflow({"capabilities": {"rules": {}}}) is False


class TestFormatCapaJob(unittest.TestCase):
    """The job payload is exactly job_id / file_hash / job_status — no stage, no
    timestamps — so the formatter must render no ETA and no elapsed time."""

    @staticmethod
    def _job(status):
        return {"job_id": "00000000-0000-0000-0000-0000000000aa", "file_hash": DUMMY_SHA256, "job_status": status}

    def test_done_points_at_the_result_fetch(self):
        out = format_capa_job(self._job("DONE"))
        assert_that(out, contains_string("DONE"))
        assert_that(out, contains_string("trigger_if_missing=False"))

    def test_failed_advises_no_retry(self):
        """A failed job does not resume on its own, so FAILED must not carry a
        retry suggestion that would loop the agent."""
        out = format_capa_job(self._job("FAILED"))
        assert_that(out, contains_string("will not progress"))
        assert_that(out, not_(contains_string("trigger_only=True")))

    def test_processing_says_poll_and_nothing_else(self):
        """A status read must not suggest a write. Telling the agent to re-trigger
        on every PROCESSING poll is a loop, and the payload cannot tell a healthy
        job from one that is stuck anyway."""
        out = format_capa_job(self._job("PROCESSING"))
        assert_that(out, not_(contains_string("trigger_only=True")))
        # The class docstring claims this formatter renders no ETA; pin it.
        assert_that(out, not_(contains_string("minute")))
        # An unbounded "keep polling" is its own trap: a job that never leaves
        # PROCESSING would be polled forever. Say when to give up instead.
        assert_that(out, contains_string("stop rather than polling indefinitely"))

    def test_created_and_queued_say_not_started_and_carry_the_same_bound(self):
        """Every polling branch needs the stop cue, not just PROCESSING: a job
        sitting in QUEUED leaves an agent in the same unbounded loop."""
        for status in ("CREATED", "QUEUED"):
            out = format_capa_job(self._job(status))
            assert_that(out, contains_string("Not started yet"))
            assert_that(out, contains_string("stop rather than polling indefinitely"))
            assert_that(out, not_(contains_string("trigger_only=True")))

    def test_status_matching_is_case_insensitive(self):
        """The API serialises these upper-case today, but a lower-cased value
        must not silently fall through to the no-hint branch."""
        assert_that(format_capa_job(self._job("done")), contains_string("trigger_if_missing=False"))

    def test_unexpected_status_is_shown_verbatim_with_no_guidance(self):
        """A CAPA job only reaches CREATED/QUEUED/PROCESSING/DONE/FAILED.
        Anything else is reported as-is rather than guessed at."""
        out = format_capa_job(self._job("SOMETHING_NEW"))
        assert_that(out, contains_string("SOMETHING_NEW"))
        assert_that(out, not_(contains_string("Not started yet")))
        assert_that(out, not_(contains_string("re-call")))
        assert_that(out, not_(contains_string("trigger_if_missing=False")))

    def test_missing_status_reports_unknown_and_offers_nothing(self):
        out = format_capa_job({})
        assert_that(out, contains_string("CAPA Analysis Job"))
        assert_that(out, contains_string("unknown"))
        assert_that(out, not_(contains_string("Not started yet")))


class TestFormatCapaJobAck(unittest.TestCase):
    def test_ack_names_the_job_id_and_the_poll_tool(self):
        out = format_capa_job_ack({"job_id": "j-1", "file_hash": DUMMY_SHA256, "job_status": "QUEUED"})
        assert_that(out, contains_string("j-1"))
        assert_that(out, contains_string("threatray_get_capa_job"))

    def test_heading_claims_neither_a_status_nor_an_action(self):
        """POST /v1/capa-analysis/jobs is get-or-create, so it can return a job
        that is already running; the heading must not contradict the status."""
        out = format_capa_job_ack({"job_id": "j-1", "file_hash": DUMMY_SHA256, "job_status": "PROCESSING"})
        assert_that(out, contains_string("PROCESSING"))
        assert_that(out, not_(contains_string("queued")))
        # The create route is get-or-create, so this call may have started nothing.
        assert_that(out, not_(contains_string("triggered")))

    def test_ack_maps_null_status_to_unknown(self):
        out = format_capa_job_ack({"job_id": "j-1", "file_hash": DUMMY_SHA256, "job_status": None})
        assert_that(out, contains_string("unknown"))
        assert_that(out, not_(contains_string("None")))

    def test_missing_fields_do_not_raise(self):
        assert_that(format_capa_job_ack({}), contains_string("unknown"))
