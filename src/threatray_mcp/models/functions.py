"""Functions section input models."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .common import HashAny, ResponseFormat, SearchScope


class FunctionsInput(BaseModel):
    """Input for listing functions from a binary."""

    model_config = ConfigDict(str_strip_whitespace=True)

    file_hash: HashAny = Field(..., description="MD5, SHA1, or SHA256 hash of the file")
    analysis_id: UUID | None = Field(
        default=None,
        description="Optional analysis ID to scope the query",
    )
    pid: int | None = Field(default=None, ge=0, description="Optional process ID for dynamic analysis")
    base: int | None = Field(default=None, ge=0, description="Optional base address for the code region")
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )


class CodeDetectionsInput(BaseModel):
    """Input for code detection results."""

    hash_sha256: HashAny = Field(
        ...,
        description="MD5, SHA1, or SHA256 hash of the code region to get detections for",
    )
    analysis_id: UUID | None = Field(
        default=None,
        description="Optional analysis UUID to scope the query",
    )
    pid: int | None = Field(default=None, ge=0, description="Optional process ID to filter results")
    base: int | None = Field(default=None, ge=0, description="Optional base address to filter results")
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )


class RetrohuntFunctionsInput(BaseModel):
    """Input for function-level retrohunt."""

    function_uids: list[str] = Field(
        ...,
        min_length=1,
        description="List of function UIDs to search for (get UIDs from threatray_list_functions)",
    )
    threshold: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Minimum ratio (0.0-1.0) of the input functions that must match in a "
        "candidate sample for it to be returned. Default 0.0 — any single matching "
        "function is enough (mirrors the backend's default ratio threshold).",
    )
    scope: SearchScope = Field(
        default=SearchScope.BOTH,
        description="Search scope: 'public' (global feed), 'private' (your data), or 'both'",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )


class DiffFunctionsInput(BaseModel):
    """Input for 1-source-to-N-targets function diff."""

    source_hash: HashAny = Field(
        ...,
        description="MD5, SHA1, or SHA256 hash of the source sample. Every function in "
                    "this sample is compared against the functions in each target.",
    )
    target_hashes: list[HashAny] = Field(
        ...,
        min_length=1,
        description="One or more MD5/SHA1/SHA256 hashes to diff the source against. "
                    "Each source function gets compared against the functions in every "
                    "target, and the per-match score / confidence / similarity are "
                    "surfaced. Pass a single hash to diff source vs one target; pass "
                    "many to find which targets carry which of the source's functions.",
    )
    with_benign_code: bool = Field(
        default=False,
        description="Include benign-classified functions on the source side. Off by "
                    "default — benign functions (runtime / library code) generate "
                    "high-similarity matches everywhere and drown out the actionable "
                    "non-benign matches.",
    )
    threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum match similarity (0.0-1.0). Matches below the threshold "
                    "are dropped before they reach the response. Default 0.5 mirrors "
                    "the IDA plugin's `Find Function Clusters` default.",
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: 'markdown' for human-readable or 'json' for machine-readable",
    )
