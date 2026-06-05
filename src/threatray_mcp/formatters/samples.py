"""Samples section formatters."""

from typing import Any

from .analyses import format_analysis_details


def format_sample_details(data: dict[str, Any]) -> str:
    """Render the response from `/v1/samples/{hash}`.

    Delegates to `format_analysis_details` — the endpoint returns the same
    `Analysis` schema as `/v1/analyses/{id}` (sample summary, processes,
    memory regions, IOCs), so a single renderer covers both.
    """
    return format_analysis_details(data)
