"""Files section — /v1/files/{hash}/{metadata,strings,data}."""

from typing import Any

from ._http import TIMEOUT_DOWNLOAD, HttpClient
from ._types import FileHashAny


class FilesClient:
    def __init__(self, http: HttpClient):
        self._http = http

    async def get_metadata(self, file_hash: FileHashAny) -> dict[str, Any]:
        """Fetch metadata for a file: PE headers, sections, imports/exports,
        resources, version info. The MCP always opts out of strings here —
        callers that want strings use `get_strings` (which hits the dedicated
        endpoint and avoids the full-buffer extraction cost on /metadata)."""
        return await self._http.get(
            f"/v1/files/{file_hash}/metadata",
            params={"include_strings": "false"},
        )

    async def get_strings(self, file_hash: FileHashAny, limit: int | None = None) -> dict[str, Any]:
        """Fetch the extracted strings list for a file. Optional `limit` caps
        the response server-side; omit for the full list."""
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        return await self._http.get(f"/v1/files/{file_hash}/strings", params=params or None)

    async def download(self, file_hash: FileHashAny, zipped: bool = True) -> bytes:
        path = f"/v1/files/{file_hash}/data"
        if zipped:
            path += "?zipped"
        return await self._http.get_binary(path, timeout=TIMEOUT_DOWNLOAD)
