"""Shared formatter helpers."""

from datetime import datetime, timezone
from typing import Any


def escape_cell(value: Any) -> str:
    """Escape a value for safe inclusion in a markdown table cell.

    Cells interpolate adversarial, sample-derived data (file names, extracted
    strings, constants, IOC values). A literal `|` injects a column; a newline
    terminates the row and corrupts every row below it — and malware strings /
    IOCs routinely contain both. Escape `|` and collapse newlines so a crafted
    sample can't forge or break the rendered table.

    `None` renders as `-` (callers usually pass already-defaulted text, but
    this keeps the helper safe to wrap around raw values too).
    """
    if value is None:
        return "-"
    return (
        str(value)
        .replace("|", "\\|")
        .replace("\r\n", " ")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def format_threats(threats_raw: list) -> str:
    """Render a threats list (strings or dicts) as a comma-separated string."""
    if not threats_raw:
        return "-"
    if isinstance(threats_raw[0], dict):
        return ", ".join(t.get("label", t.get("key", str(t))) for t in threats_raw) or "-"
    return ", ".join(str(t) for t in threats_raw) or "-"


def format_timestamp(value: Any, *, date_only: bool = False) -> str:  # noqa: PLR0911
    """Render a timestamp value as a human-readable string.

    Accepts the shapes the public API surfaces:
    - `int` / `float` Unix epoch seconds (e.g. `1748591903`)
    - ISO-8601 string (e.g. `"2025-05-30T10:05:44"` or with `Z` / `+00:00`)
    - `{source, parsedValue}` wrapper dict — recurses on `parsedValue`
    - `None` / empty string → `-`

    Output:
    - `date_only=False` (default) → `YYYY-MM-DD HH:MM:SS UTC` for epoch input,
      ISO string trimmed to seconds precision otherwise.
    - `date_only=True` → `YYYY-MM-DD`.

    Unparseable values fall through as `str(value)` rather than raising — the
    caller is rendering markdown, not parsing data."""
    if value is None or value == "":
        return "-"
    if isinstance(value, dict) and "parsedValue" in value:
        return format_timestamp(value["parsedValue"], date_only=date_only)
    if isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(int(value), tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return str(value)
        return dt.strftime("%Y-%m-%d") if date_only else dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    text = str(value)
    if date_only:
        return text[:10]
    # ISO strings: re-emit in the same `YYYY-MM-DD HH:MM:SS UTC` form epoch
    # inputs produce so every tool's full-datetime output is uniform.
    # `2026-05-20T09:55:06.352971Z` → `2026-05-20 09:55:06 UTC`.
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
