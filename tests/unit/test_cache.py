"""Tests for the markdown spill-to-disk cache."""

import os
import stat
import tempfile
import unittest

from hamcrest import assert_that, contains_string, equal_to, not_

# Ensure the package config can load before we import internals.
os.environ.setdefault("THREATRAY_API_KEY", "test-key")
os.environ.setdefault("THREATRAY_API_URL", "https://api.threatray.test")

from threatray_mcp.tools import _cache


class TestFormatWithCache(unittest.TestCase):
    def setUp(self):
        # Redirect the cache dir to a temp area so the test doesn't litter
        # the user's real ~/.cache.
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = _cache.RESULT_CACHE_DIR
        _cache.RESULT_CACHE_DIR = type(_cache.RESULT_CACHE_DIR)(self._tmp.name)

    def tearDown(self):
        _cache.RESULT_CACHE_DIR = self._orig_dir
        self._tmp.cleanup()

    def test_under_threshold_returns_summary_only(self):
        out = _cache.format_with_cache(
            summary="short summary",
            full_markdown="full text",
            prefix="test",
            item_count=5,
            threshold=10,
        )
        assert_that(out, equal_to("short summary"))

    def test_over_threshold_spills_markdown_and_appends_pointer(self):
        full_md = "# Full\n\n| col |\n|---|\n" + "\n".join(f"| row {i} |" for i in range(50))
        out = _cache.format_with_cache(
            summary="short summary (showing 10 of 50)",
            full_markdown=full_md,
            prefix="test",
            item_count=50,
            threshold=10,
        )
        # Pointer is appended.
        assert_that(out, contains_string("short summary (showing 10 of 50)"))
        assert_that(out, contains_string("Full markdown (50 items) saved to:"))
        assert_that(out, contains_string(".md"))
        # The pointer must NOT mention JSON — spill format is markdown.
        assert_that(out, not_(contains_string("JSON file")))
        # Cache file was actually written with the full_markdown contents.
        cache_files = list(_cache.RESULT_CACHE_DIR.glob("test_*.md"))
        self.assertEqual(len(cache_files), 1)
        self.assertEqual(cache_files[0].read_text(), full_md)

    def test_spill_filename_uses_md_suffix(self):
        _cache.format_with_cache(
            summary="s",
            full_markdown="m",
            prefix="capa",
            item_count=100,
            threshold=10,
        )
        files = list(_cache.RESULT_CACHE_DIR.iterdir())
        self.assertEqual(len(files), 1)
        self.assertTrue(files[0].name.startswith("capa_"))
        self.assertTrue(files[0].name.endswith(".md"))

    def test_force_spill_routes_to_disk_even_under_threshold(self):
        """`force_spill=True` is the search/retrohunt_sample knob for
        bucket-overflow: response has only 3 analyses (well under the
        threshold) but a 100-rule YARA bucket means the long tail would be
        silently truncated. The full markdown must spill anyway."""
        out = _cache.format_with_cache(
            summary="3 analyses (YARA bucket has 100 hits, 25 shown)",
            full_markdown="# Full with all 100 rules",
            prefix="search",
            item_count=3,
            threshold=50,
            force_spill=True,
        )
        assert_that(out, contains_string("Full markdown (3 items) saved to:"))
        # Cache file was actually written.
        cache_files = list(_cache.RESULT_CACHE_DIR.glob("search_*.md"))
        self.assertEqual(len(cache_files), 1)
        self.assertEqual(cache_files[0].read_text(), "# Full with all 100 rules")


class TestCacheHardening(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_dir = _cache.RESULT_CACHE_DIR
        _cache.RESULT_CACHE_DIR = type(_cache.RESULT_CACHE_DIR)(self._tmp.name)
        _cache._session_cache_files.clear()

    def tearDown(self):
        _cache.RESULT_CACHE_DIR = self._orig_dir
        self._tmp.cleanup()

    def test_two_spills_same_prefix_do_not_collide(self):
        # Same prefix written back-to-back (same wall-clock second) must NOT
        # overwrite each other — each spill gets a unique file.
        p1 = _cache._save_to_cache("content one", "search")
        p2 = _cache._save_to_cache("content two", "search")
        self.assertNotEqual(p1, p2)
        self.assertEqual(p1.read_text(), "content one")
        self.assertEqual(p2.read_text(), "content two")

    def test_spill_file_is_owner_only(self):
        p = _cache._save_to_cache("secret intel", "test")
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)

    def test_cache_dir_is_owner_only(self):
        _cache._save_to_cache("x", "test")
        self.assertEqual(stat.S_IMODE(_cache.RESULT_CACHE_DIR.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
