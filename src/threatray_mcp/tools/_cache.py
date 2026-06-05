"""Large-result spill-to-file cache shared by tools.

Spill format is markdown: the full markdown view the formatter would produce
is written to disk so the agent navigates the spill with the same Read /
offset / limit pattern it uses for the inline summary, against the same
formatting choices. The formatter is the single source of truth for what the
LLM sees at every viewing level.
"""

import atexit
import os
import sys
import time
from pathlib import Path

CACHE_FILE_SUFFIX = ".md"


def _get_cache_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or os.path.expanduser("~")
        return Path(base) / "threatray_mcp" / "cache"
    xdg_cache = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return Path(xdg_cache) / "threatray_mcp"


RESULT_CACHE_DIR = _get_cache_dir()
CACHE_TTL_SECONDS = 3600
LARGE_RESULT_THRESHOLD = 30
_session_cache_files: list[Path] = []


def _cleanup_old_cache_files() -> None:
    if not RESULT_CACHE_DIR.exists():
        return
    now = time.time()
    for f in RESULT_CACHE_DIR.glob(f"*{CACHE_FILE_SUFFIX}"):
        try:
            if now - f.stat().st_mtime > CACHE_TTL_SECONDS:
                f.unlink(missing_ok=True)
        except OSError:
            pass


def _cleanup_session_files() -> None:
    for f in _session_cache_files:
        try:
            f.unlink(missing_ok=True)
        except OSError:
            pass


atexit.register(_cleanup_session_files)


def _save_to_cache(content: str, prefix: str) -> Path:
    RESULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _cleanup_old_cache_files()

    filename = f"{prefix}_{int(time.time())}{CACHE_FILE_SUFFIX}"
    filepath = RESULT_CACHE_DIR / filename
    filepath.write_text(content)
    _session_cache_files.append(filepath)
    return filepath


def format_with_cache(
    summary: str,
    full_markdown: str,
    prefix: str,
    item_count: int,
    threshold: int = LARGE_RESULT_THRESHOLD,
    force_spill: bool = False,
) -> str:
    """Return summary as-is, or spill the full markdown to disk and append a
    pointer when item_count exceeds threshold. `force_spill=True` routes the
    full markdown to disk regardless of item_count — used by search and
    retrohunt_sample when the inline summary truncates the long tail of an
    aggregation bucket (YARA, family, AV …)."""
    if not force_spill and item_count <= threshold:
        return summary

    filepath = _save_to_cache(full_markdown, prefix)
    return f"""{summary}

---
*Full markdown ({item_count} items) saved to: `{filepath}`*
*Use Read tool with offset/limit parameters to browse the full file.*"""
