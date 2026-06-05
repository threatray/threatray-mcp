"""Search section — /v1/search (incl. retrohunt-by-sample variant)."""

from typing import Any

from ..models import SearchScope
from ._http import TIMEOUT_LONG, HttpClient
from ._types import DateRange, FileHashAny


class SearchClient:
    def __init__(self, http: HttpClient):
        self._http = http

    async def run(
        self,
        query: str,
        max_results: int = 50,
        scope: SearchScope = SearchScope.BOTH,
        date: DateRange | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "query": query,
            "max_results": max_results,
            "scope": scope,
        }
        if date:
            params["date"] = date
        return await self._http.get("/v1/search", params, timeout=TIMEOUT_LONG)

    async def retrohunt_sample(
        self,
        sample_hash: FileHashAny,
        max_results: int = 50,
        scope: SearchScope = SearchScope.BOTH,
        date: DateRange | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "query": f"retrohunt: {sample_hash}",
            "max_results": max_results,
            "scope": scope,
        }
        if date:
            params["date"] = date
        return await self._http.get("/v1/search", params, timeout=TIMEOUT_LONG)
