"""AI Analysis section input models."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .common import HashSha256, ResponseFormat


class AiAnalysisInput(BaseModel):
    """Input for AI-powered analysis of a file."""

    model_config = ConfigDict(str_strip_whitespace=True)

    file_hash: HashSha256 = Field(..., description="SHA256 hash of the file to analyze")
    trigger_if_missing: bool = Field(
        default=True,
        description="If True, create an AI analysis job when no result exists yet. "
        "Combined with `trigger_only=False`, the tool waits up to `max_wait_seconds`. "
        "With `trigger_only=True`, the tool returns the job-id immediately and the "
        "caller polls later via `threatray_get_latest_ai_job`.",
    )
    trigger_only: bool = Field(
        default=False,
        description="If True, trigger the job and return without polling for completion. Useful for "
        "fire-and-forget kicks on slow files; check progress later via `threatray_get_latest_ai_job`.",
    )
    max_wait_seconds: int = Field(
        default=600,
        ge=30,
        le=3600,
        description="Maximum seconds to wait for job completion when `trigger_only=False`. "
        "Server-side AI processing can take a long time; default 600s (10 minutes), upper bound "
        "3600s (1 hour). Ignored when `trigger_only=True`.",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )


class AiAnalysisResultsInput(BaseModel):
    """Input for listing AI analysis results for a file."""

    model_config = ConfigDict(str_strip_whitespace=True)

    file_hash: HashSha256 = Field(..., description="SHA256 hash of the file")
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )


class AiAnalysisByIdInput(BaseModel):
    """Input for `threatray_get_ai_analysis_by_id`."""

    analysis_id: UUID = Field(..., description="AI-analysis result UUID")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class AiLatestJobInput(BaseModel):
    """Input for `threatray_get_latest_ai_job`."""

    model_config = ConfigDict(str_strip_whitespace=True)

    file_hash: HashSha256 = Field(..., description="SHA256 hash of the file")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")
