"""Presentation helpers for AI-analysis job status payloads."""

from datetime import datetime, timezone
from math import ceil, floor, isfinite
from typing import Any

from .models.common import JobStatus

_STAGE_LABELS = {
    "PREPARING": "Preparing",
    "DECOMPILING": "Decompiling code",
    "ANALYZING": "AI review",
    "SYNTHESIZING": "Building verdict",
}


def ai_analysis_stage_label(stage: Any) -> str | None:
    if stage is None or stage == "":
        return None
    text = str(stage)
    return _STAGE_LABELS.get(text, text.replace("_", " ").title())


def format_ai_analysis_elapsed(
    job: dict[str, Any],
    *,
    now: datetime | None = None,
) -> str | None:
    if _normalized_status(job.get("job_status")) != JobStatus.PROCESSING.value:
        return None
    started_at = _parse_datetime(job.get("started_at"))
    if started_at is None:
        return None
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    elapsed_seconds = max(0, int((current.astimezone(timezone.utc) - started_at).total_seconds()))
    return _format_duration(elapsed_seconds)


def format_ai_analysis_remaining(job: dict[str, Any]) -> str | None:
    if (status := job.get("job_status")) is not None and _normalized_status(status) != JobStatus.PROCESSING.value:
        return None
    estimate = job.get("remaining_time_estimate")
    if not isinstance(estimate, dict):
        return None
    minimum_raw = _numeric_seconds(estimate.get("minimum_seconds"))
    maximum_raw = _numeric_seconds(estimate.get("maximum_seconds"))
    if minimum_raw is None or maximum_raw is None or minimum_raw < 0 or maximum_raw < minimum_raw:
        return None
    minimum = floor(minimum_raw)
    maximum = ceil(maximum_raw)
    low = _format_rough_duration(minimum, round_up=False)
    high = _format_rough_duration(maximum, round_up=True)
    if low == high:
        return f"about {low} remaining"
    return f"about {low}-{high} remaining"


def format_ai_analysis_job_progress(job: dict[str, Any]) -> str:
    status = _normalized_status(job.get("job_status"))
    stage = ai_analysis_stage_label(job.get("stage"))
    if status in (JobStatus.CREATED.value, JobStatus.QUEUED.value):
        activity = "Waiting for a worker"
    elif status == JobStatus.DONE.value:
        activity = "Complete"
    elif status in (JobStatus.FAILED.value, JobStatus.UNSUPPORTED.value, JobStatus.SKIPPED.value):
        activity = status.title()
    else:
        activity = stage or status.title() or "Processing"

    parts = [f"AI analysis: {activity}"]
    if elapsed := format_ai_analysis_elapsed(job):
        parts.append(f"elapsed {elapsed}")
    if remaining := format_ai_analysis_remaining(job):
        parts.append(remaining)
    elif status == JobStatus.PROCESSING.value:
        parts.append("remaining time unavailable")
    return " · ".join(parts)


def _normalized_status(value: Any) -> str:
    return str(value or "").upper()


def _numeric_seconds(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    seconds = float(value)
    return seconds if isfinite(seconds) else None


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_duration(seconds: int) -> str:
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _format_rough_duration(seconds: int, *, round_up: bool) -> str:
    round_units = ceil if round_up else floor
    if seconds < 60:
        rounded_seconds = max(5, round_units(seconds / 5) * 5)
        return f"{rounded_seconds}s"
    total_minutes = max(1, round_units(seconds / 60))
    hours, minutes = divmod(total_minutes, 60)
    if hours and minutes:
        return f"{hours}h {minutes}m"
    if hours:
        return f"{hours}h"
    return f"{minutes}m"
