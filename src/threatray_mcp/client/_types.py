"""Internal type aliases shared by section clients."""

from collections.abc import Awaitable, Callable
from typing import NewType

ProgressCallback = Callable[[float, str], Awaitable[None]] | None

# Narrowed string types — used in client method signatures so the caller has
# a chance to confuse md5/sha1/sha256 only at a single boundary (the input
# model). Runtime is still `str`; this is a static-typing aid.

FileHashAny = NewType("FileHashAny", str)
"""md5, sha1, or sha256 hex hash. Used by tools that accept any of the three."""

FileHashSha256 = NewType("FileHashSha256", str)
"""Strict sha256 hex hash. Used by endpoints whose backend rejects shorter hashes
(CAPA, AI analysis)."""

FunctionUid = NewType("FunctionUid", str)
"""Stable function identifier produced by `threatray_list_functions` (e.g. `CFF.6490927083070388341`)."""

DateRange = NewType("DateRange", str)
"""Relative time window in 'Nd' format: '7d' (last 7 days), '0d' (all time). Used by
search / retrohunt."""

IsoDateTime = NewType("IsoDateTime", str)
"""ISO-8601 datetime (e.g. '2026-01-01T00:00:00Z'). Used by the cursor-paginated
analyses listings."""

SampleAnalysisId = NewType("SampleAnalysisId", str)
"""Identifier of a sample analysis (UUID-shaped). Returned by /v1/analyses/* and
used by /v1/functions/{hash}?analysis_id=..., /v1/tasks/by-analysis/{id}, etc.
A sample can have multiple sample-analyses; this disambiguates between them."""

AiAnalysisId = NewType("AiAnalysisId", str)
"""Identifier of an AI analysis result (UUID-shaped). Distinct from
SampleAnalysisId — used by /v1/ai-analysis/results/{id}."""

TaskId = NewType("TaskId", int)
"""Numeric task id returned by /v1/submissions/* and /v1/tasks/*. Tasks track
the lifecycle of a single submission as it moves through the analysis pipeline."""

SubmissionId = NewType("SubmissionId", str)
"""UUID-shaped submission identifier. A submission can produce multiple tasks
(e.g. one per file in an archive)."""
