"""Presentation helpers for AI-analysis job status payloads.

Keep the user-facing copy and duration formatting aligned with the Threatray UI's
``ai-analysis-progress`` and ``format-ai-analysis-estimate`` utilities.
"""

from datetime import datetime, timezone
from math import floor, isfinite
from typing import Any

from .models import JobStatus

_STAGE_LABELS = {
    "PREPARING": "Preparing analysis",
    "DECOMPILING": "Decompiling code",
    "ANALYZING": "Analyzing functions",
    "SYNTHESIZING": "Finalizing results",
}
_STAGES = tuple(_STAGE_LABELS)
_ESTIMATED_STAGES = frozenset(("DECOMPILING", "ANALYZING", "SYNTHESIZING"))
_RANGE_SEPARATOR = "\N{EN DASH}"


def ai_analysis_stage_label(stage: Any) -> str | None:
    if stage is None or stage == "":
        return None
    return _STAGE_LABELS.get(_normalized_stage(stage), "Analyzing")


def ai_analysis_stage_step(job: dict[str, Any]) -> str | None:
    stage = _normalized_stage(job.get("stage"))
    try:
        index = _STAGES.index(stage)
    except ValueError:
        return None
    return f"Step {index + 1} of {len(_STAGES)}"


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
    if _normalized_status(job.get("job_status")) != JobStatus.PROCESSING.value:
        return None
    estimate = job.get("remaining_time_estimate")
    if not isinstance(estimate, dict):
        stage = _normalized_stage(job.get("stage"))
        return "Taking longer than expected" if stage in _ESTIMATED_STAGES else None
    minimum_raw = _numeric_seconds(estimate.get("minimum_seconds"))
    maximum_raw = _numeric_seconds(estimate.get("maximum_seconds"))
    if minimum_raw is None or maximum_raw is None or minimum_raw < 0 or maximum_raw < minimum_raw:
        return None
    return _format_compact_estimate(minimum_raw, maximum_raw)


def format_ai_analysis_job_progress(
    job: dict[str, Any],
    *,
    now: datetime | None = None,
) -> str:
    status = _normalized_status(job.get("job_status"))
    stage = ai_analysis_stage_label(job.get("stage"))
    if status in (JobStatus.CREATED.value, JobStatus.QUEUED.value):
        activity = "Analysis queued"
    elif status == JobStatus.DONE.value:
        activity = "Complete"
    elif status in (JobStatus.FAILED.value, JobStatus.UNSUPPORTED.value, JobStatus.SKIPPED.value):
        activity = status.title()
    else:
        activity = stage or "Analyzing"

    parts = [f"AI analysis: {activity}"]
    if status == JobStatus.PROCESSING.value and (step := ai_analysis_stage_step(job)):
        parts.append(step)
    if remaining := format_ai_analysis_remaining(job):
        parts.append(remaining)
    if elapsed := format_ai_analysis_elapsed(job, now=now):
        parts.append(f"{elapsed} elapsed")
    return " · ".join(parts)


def _normalized_status(value: Any) -> str:
    return str(value or "").upper()


def _normalized_stage(value: Any) -> str:
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
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    return f"{minutes}:{seconds:02d}"


def _format_compact_estimate(minimum_seconds: float, maximum_seconds: float) -> str:
    if maximum_seconds < 60:
        low = _rounded_seconds(minimum_seconds)
        high = _rounded_seconds(maximum_seconds)
        value = f"{low}s" if low == high else f"{low}{_RANGE_SEPARATOR}{high}s"
    elif minimum_seconds >= 60:
        low = _rounded_minutes(minimum_seconds)
        high = _rounded_minutes(maximum_seconds)
        value = f"{low}m" if low == high else f"{low}{_RANGE_SEPARATOR}{high}m"
    else:
        value = f"{_format_estimate_bound(minimum_seconds)}{_RANGE_SEPARATOR}{_format_estimate_bound(maximum_seconds)}"
    return f"{value} left"


def _format_estimate_bound(seconds: float) -> str:
    if seconds < 60:
        return f"{_rounded_seconds(seconds)}s"
    return f"{_rounded_minutes(seconds)}m"


def _rounded_seconds(seconds: float) -> int:
    return max(5, floor(seconds / 5 + 0.5) * 5)


def _rounded_minutes(seconds: float) -> int:
    return max(1, floor(seconds / 60 + 0.5))
