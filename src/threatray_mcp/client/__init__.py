"""Threatray API client — section-based architecture.

Public entrypoint is `ThreatrayClient`, which exposes section sub-clients as attributes:
`client.search`, `client.samples`, `client.analyses`, `client.submissions`, `client.files`,
`client.functions`, `client.capa`, `client.ai_analysis`.

Errors raised by section clients are subclasses of `threatray_mcp.errors.ThreatrayError`.
"""

import httpx

from ._http import HttpClient
from ._types import ProgressCallback
from .ai_analysis import AiAnalysisClient
from .analyses import AnalysesClient
from .capa import CapaClient
from .files import FilesClient
from .functions import FunctionsClient
from .samples import SamplesClient
from .search import SearchClient
from .submissions import SubmissionsClient


class ThreatrayClient:
    """Facade aggregating per-section clients over a shared HttpClient."""

    def __init__(self, http_client: httpx.AsyncClient | HttpClient | None = None):
        if isinstance(http_client, HttpClient):
            self._http = http_client
        else:
            self._http = HttpClient(http_client=http_client)

        self.search = SearchClient(self._http)
        self.samples = SamplesClient(self._http)
        self.analyses = AnalysesClient(self._http)
        self.submissions = SubmissionsClient(self._http)
        self.files = FilesClient(self._http)
        self.functions = FunctionsClient(self._http)
        self.capa = CapaClient(self._http)
        self.ai_analysis = AiAnalysisClient(self._http)


__all__ = [
    "AiAnalysisClient",
    "AnalysesClient",
    "CapaClient",
    "FilesClient",
    "FunctionsClient",
    "HttpClient",
    "ProgressCallback",
    "SamplesClient",
    "SearchClient",
    "SubmissionsClient",
    "ThreatrayClient",
]
