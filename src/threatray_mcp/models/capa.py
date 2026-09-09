"""CAPA section input models."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .common import HashSha256, ResponseFormat


class CapaInput(BaseModel):
    """Input for CAPA capability analysis."""

    model_config = ConfigDict(str_strip_whitespace=True)

    file_hash: HashSha256 = Field(..., description="SHA256 hash of the file to analyze")
    trigger_if_missing: bool = Field(
        default=True,
        description="If True, trigger an analysis job when no result exists yet and wait for it to complete.",
    )
    trigger_only: bool = Field(
        default=False,
        description="If True, create the job and return its id immediately without polling. "
        "Useful for fire-and-forget kicks on slow files; poll the returned job-id with "
        "`threatray_get_capa_job`, then fetch the result with "
        "`threatray_get_capa(file_hash, trigger_if_missing=False)`. Returns a job-id only "
        "when no CAPA result exists yet; otherwise the existing result is returned.",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )


class CapaJobInput(BaseModel):
    """Input for `threatray_get_capa_job`."""

    job_id: UUID = Field(..., description="CAPA job UUID, as returned by `threatray_get_capa(trigger_only=True)`")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN, description="Output format")
