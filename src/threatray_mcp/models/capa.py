"""CAPA section input models."""

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
        "Useful for fire-and-forget kicks on slow files; caller can re-call later "
        "to fetch the completed result.",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )
