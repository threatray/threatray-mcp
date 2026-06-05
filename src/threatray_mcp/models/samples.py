"""Samples section input models."""

from pydantic import BaseModel, ConfigDict, Field

from .common import HashAny, ResponseFormat


class SampleHashInput(BaseModel):
    """Input for sample lookup by hash."""

    model_config = ConfigDict(str_strip_whitespace=True)

    sample_hash: HashAny = Field(..., description="MD5, SHA1, or SHA256 hash of the sample")
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )
