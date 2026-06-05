"""Analyses section input models."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .common import HashAny, ResponseFormat, Verdict


class AnalysisIdInput(BaseModel):
    """Input for analysis lookup by ID."""

    analysis_id: UUID = Field(
        ...,
        description="Analysis UUID (e.g., '00000000-0000-0000-0000-000000000001')",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )


class OsintInput(BaseModel):
    """Input for OSINT lookup by sample hash."""

    hash: HashAny = Field(..., description="Sample hash (md5, sha1, or sha256)")
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )


class _AnalysesPageInput(BaseModel):
    """Shared input for the cursor-paginated /v1/analyses/* endpoints."""

    model_config = ConfigDict(str_strip_whitespace=True)

    verdicts: list[Verdict] | None = Field(
        default=None,
        description="Filter by verdicts: any subset of ['unknown', 'suspicious', 'malicious']. "
        "Omit to use the server default (all three).",
    )
    from_finished_at: str | None = Field(
        default=None,
        description="ISO-8601 lower bound on analysis_finished (e.g. '2026-01-01T00:00:00Z').",
    )
    to_finished_at: str | None = Field(
        default=None,
        description="ISO-8601 upper bound on analysis_finished (e.g. '2026-12-31T23:59:59Z').",
    )
    limit: int = Field(default=200, ge=1, le=200, description="Maximum analyses to return (1-200)")
    cursor: str | None = Field(
        default=None,
        description="Page cursor from a previous response's `cursor` field. Omit for the first page.",
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")


class AnalysesListInput(_AnalysesPageInput):
    """Input for `threatray_list_analyses` — paginated list of sample analyses."""


class EndpointScanAnalysesListInput(_AnalysesPageInput):
    """Input for `threatray_list_endpoint_scan_analyses` — paginated endpoint-scan analyses."""
