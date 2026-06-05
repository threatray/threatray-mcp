"""Cross-section enums, hash validators, and shared constants.

All string enums use `StrEnum` (Python 3.11+) so that `str(MyEnum.VALUE)` yields
the value (e.g. "both"), not the repr ("SearchScope.BOTH"). httpx URL-encodes
params by calling `str()`, so passing a non-StrEnum would produce broken query
strings the backend rejects with 400.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, BeforeValidator


class ResponseFormat(StrEnum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


class SearchScope(StrEnum):
    """Scope for search and retrohunt operations."""

    PUBLIC = "public"
    PRIVATE = "private"
    BOTH = "both"


class SubmissionStatus(StrEnum):
    """Status filter for sample submissions (mirrors OpenAPI `status` enum)."""

    ALL = ""
    QUEUED = "queued"
    ANALYZING = "analyzing"
    DONE = "done"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


class JobStatus(StrEnum):
    """Status of analysis jobs (CAPA, AI analysis)."""

    CREATED = "CREATED"
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    DONE = "DONE"
    FAILED = "FAILED"
    UNSUPPORTED = "UNSUPPORTED"
    SKIPPED = "SKIPPED"


class AnalysisMode(StrEnum):
    """Submission analysis mode (OpenAPI `analysis_mode` enum)."""

    STATIC = "static"
    DYNAMIC = "dynamic"


class Priority(StrEnum):
    """Submission priority tier (OpenAPI `Priority` enum)."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class Verdict(StrEnum):
    """Sample / analysis verdict filter vocabulary.

    The list-analysis filter endpoints (`/v1/analyses/samples`,
    `/v1/analyses/endpoint-scans`) accept these three values as
    `verdicts=` query params. Response payloads may carry an additional
    `benign` verdict on code-detection sub-records, but `benign` is not a
    valid filter input. Formatters surface it verbatim when present."""

    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class RawBinaryFileFormat(StrEnum):
    """Raw-binary submission format (OpenAPI `raw_binary_file_format`)."""

    UNKNOWN = "unknown"
    RAW = "raw"
    PE = "pe"


class RawBinaryCpuArchitecture(StrEnum):
    """Raw-binary CPU architecture (OpenAPI `raw_binary_cpu_architecture`)."""

    UNSET = ""
    X86_32 = "x86-32"
    X86_64 = "x86-64"


_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_VALID_HASH_LENGTHS = (32, 40, 64)


def _normalize_hex(v: str) -> str:
    if not isinstance(v, str):
        raise TypeError("hash must be a string")
    return v.strip().lower()


def _validate_hash_any(v: str) -> str:
    if not _HEX_RE.match(v):
        raise ValueError("hash must be hexadecimal characters only")
    if len(v) not in _VALID_HASH_LENGTHS:
        raise ValueError("hash must be md5 (32), sha1 (40), or sha256 (64) hex characters")
    return v


def _validate_hash_sha256(v: str) -> str:
    if not _HEX_RE.match(v):
        raise ValueError("hash must be hexadecimal characters only")
    if len(v) != 64:
        raise ValueError("hash must be a sha256 (64 hex characters); md5/sha1 are not accepted here")
    return v


HashAny = Annotated[str, BeforeValidator(_normalize_hex), AfterValidator(_validate_hash_any)]
"""Accept md5 (32), sha1 (40), or sha256 (64) hex hashes. Whitespace stripped, lower-cased."""

HashSha256 = Annotated[str, BeforeValidator(_normalize_hex), AfterValidator(_validate_hash_sha256)]
"""Strict sha256-only validator. Used for endpoints (CAPA, AI analysis) whose backend rejects shorter hashes."""
