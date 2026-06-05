"""Search section input models."""

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .common import HashAny, ResponseFormat, SearchScope

_DATE_RE = re.compile(r"^\d+d$")
_DATE_HELP = (
    "Time filter in 'Nd' format: '7d' (last 7 days), '30d' (last 30 days), '0d' (all time)."
)


def _validate_date(v: str | None) -> str | None:
    if v is None:
        return v
    v = v.strip().lower()
    if not _DATE_RE.match(v):
        raise ValueError("date must be in 'Nd' format, e.g. '7d', '30d', or '0d' (all time)")
    return v


class SearchInput(BaseModel):
    """Input for threat search operations."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(
        ...,
        min_length=1,
        description="Search query with optional operators (e.g., 'signature:Emotet', 'ip:192.168.1.0/24')",
    )
    max_results: int = Field(
        default=50,
        ge=1,
        le=10000,
        description="Maximum results to return. Default 50; backend hard ceiling 10000.",
    )
    scope: SearchScope = Field(
        default=SearchScope.BOTH,
        description="Search scope: 'public' (global feed), 'private' (your data), or 'both'",
    )
    date: str | None = Field(default=None, description=_DATE_HELP)
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )

    _vd = field_validator("date")(_validate_date)


class RetrohuntSampleInput(BaseModel):
    """Input for sample-based retrohunt (code similarity search)."""

    model_config = ConfigDict(str_strip_whitespace=True)

    sample_hash: HashAny = Field(
        ...,
        description="MD5, SHA1, or SHA256 hash of the sample to find similar samples for",
    )
    max_results: int = Field(
        default=50,
        ge=1,
        le=10000,
        description="Maximum similar samples to return. Default 50; backend hard ceiling 10000.",
    )
    scope: SearchScope = Field(
        default=SearchScope.BOTH,
        description="Search scope: 'public' (global feed), 'private' (your data), or 'both'",
    )
    date: str | None = Field(default=None, description=_DATE_HELP)
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )

    _vd = field_validator("date")(_validate_date)
