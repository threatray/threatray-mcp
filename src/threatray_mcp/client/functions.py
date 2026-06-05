"""Functions section — /v1/functions/*, /v1/retrohunt/functions, /v1/functions/diff."""

from __future__ import annotations

from typing import Any

from ..models import SearchScope
from ._http import TIMEOUT_CODE_DETECTIONS, TIMEOUT_FUNCTIONS_DIFF, TIMEOUT_LONG, HttpClient
from ._types import FileHashAny, FunctionUid, SampleAnalysisId


class FunctionsClient:
    def __init__(self, http: HttpClient):
        self._http = http

    async def list_functions(
        self,
        file_hash: FileHashAny,
        analysis_id: SampleAnalysisId | None = None,
        pid: int | None = None,
        base: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if analysis_id:
            params["analysis_id"] = analysis_id
        if pid is not None:
            params["pid"] = pid
        if base is not None:
            params["base"] = base
        return await self._http.get(f"/v1/functions/{file_hash}", params)

    async def get_code_detections(
        self,
        file_hash: FileHashAny,
        analysis_id: SampleAnalysisId | None = None,
        pid: int | None = None,
        base: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"hash": file_hash}
        if analysis_id:
            params["analysis_id"] = analysis_id
        if pid is not None:
            params["pid"] = pid
        if base is not None:
            params["base"] = base
        return await self._http.get("/v1/functions/code-detections", params, timeout=TIMEOUT_CODE_DETECTIONS)

    async def run_retrohunt(
        self,
        function_uids: list[FunctionUid],
        threshold: float = 0.0,
        scope: SearchScope = SearchScope.BOTH,
    ) -> dict[str, Any]:
        # The single-uid case is duplicated to satisfy a backend constraint;
        # the threshold ratio is preserved.
        if len(function_uids) == 1:
            function_uids = [function_uids[0], function_uids[0]]
        params: dict[str, Any] = {
            "uids": function_uids,
            "threshold": threshold,
            "scope": scope,
        }
        return await self._http.get("/v1/retrohunt/functions", params, timeout=TIMEOUT_LONG)

    async def diff(
        self,
        source_hash: FileHashAny,
        target_hashes: list[FileHashAny],
        with_benign_code: bool = False,
        threshold: float = 0.5,
    ) -> dict[str, Any]:
        data = {
            "source_file": {"hash": source_hash},
            "target_files": [{"hash": h} for h in target_hashes],
            "threshold": threshold,
            "with_benign_code": with_benign_code,
        }
        return await self._http.post("/v1/functions/diff", data, timeout=TIMEOUT_FUNCTIONS_DIFF)
