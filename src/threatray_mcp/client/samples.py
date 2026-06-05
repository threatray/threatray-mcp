"""Samples section — /v1/samples/{hash}."""

from typing import Any

from ._http import HttpClient
from ._types import FileHashAny


class SamplesClient:
    def __init__(self, http: HttpClient):
        self._http = http

    async def get(self, sample_hash: FileHashAny) -> dict[str, Any]:
        return await self._http.get(f"/v1/samples/{sample_hash}")
