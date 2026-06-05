"""Tests for formatters/capa.py — mocks mirror the actual CAPA payload shape."""

import unittest

from hamcrest import assert_that, contains_string, not_

from tests.dummies import DUMMY_SHA256
from threatray_mcp.formatters import format_capa_results
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
