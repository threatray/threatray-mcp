"""Exception hierarchy for the Threatray client and MCP tools.

FastMCP propagates uncaught exceptions as MCP tool errors, so tool functions
no longer need to swallow exceptions into string returns.
"""


class ThreatrayError(Exception):
    """Base for all Threatray client/MCP errors."""

    def __init__(self, message: str, status_code: int | None = None):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class ThreatrayBadRequest(ThreatrayError):
    """400 — malformed request. Pydantic input models usually prevent this."""


class ThreatrayAuthError(ThreatrayError):
    """401 — invalid or expired API key (check THREATRAY_API_KEY)."""


class ThreatrayForbiddenError(ThreatrayError):
    """403 — authenticated but lacking permission for this resource."""


class ThreatrayNotFound(ThreatrayError):
    """404 — resource not found (e.g., unknown hash, analysis id, or job)."""


class ThreatrayFeatureUnavailable(ThreatrayError):
    """The feature behind this endpoint is not enabled for the caller's Threatray
    account. Mapped at the section-client layer when an upstream 404 is known to
    indicate feature-off rather than a missing resource (AI analysis, clustering)."""


class ThreatrayRateLimitError(ThreatrayError):
    """429 — rate limit hit; back off and retry."""


class ThreatrayServerError(ThreatrayError):
    """5xx — upstream server fault."""


class ThreatrayTimeoutError(ThreatrayError):
    """Network or server timeout."""


class ThreatrayConnectionError(ThreatrayError):
    """Network connection failed (DNS, TLS, refused, etc.)."""


class ThreatrayJobFailed(ThreatrayError):
    """Async job (CAPA, AI analysis) terminated in a FAILED/UNSUPPORTED/SKIPPED state."""


class ThreatrayJobTimeout(ThreatrayError):
    """Async job polling exceeded the timeout budget."""
