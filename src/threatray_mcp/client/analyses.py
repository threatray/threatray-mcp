"""Analyses section — /v1/analyses/{id}, /v1/osint/{hash}, paginated listings.

The detailed-analysis fetch is exposed in tools as `threatray_get_analysis`; the
osint-per-hash fetch as `threatray_get_osint`.
"""

from typing import Any

from ..models import Verdict
from ._http import HttpClient
from ._types import FileHashAny, IsoDateTime, SampleAnalysisId


def _verdict_params(verdicts: list[Verdict] | None) -> list[str] | None:
    if not verdicts:
        return None
    # Coerce each entry through the Verdict StrEnum so bogus strings raise here
    # rather than reaching the API as a bad query param. Pydantic already
    # enforces this at the tool boundary; this is a defence-in-depth check for
    # callers who go straight through the client.
    return [Verdict(v).value for v in verdicts]


class AnalysesClient:
    def __init__(self, http: HttpClient):
        self._http = http

    async def get(self, analysis_id: SampleAnalysisId) -> dict[str, Any]:
        return await self._http.get(f"/v1/analyses/{analysis_id}")

    async def osint(self, sample_hash: FileHashAny) -> dict[str, Any]:
        return await self._http.get(f"/v1/osint/{sample_hash}")

    async def list_samples(
        self,
        *,
        verdicts: list[Verdict] | None = None,
        from_finished_at: IsoDateTime | None = None,
        to_finished_at: IsoDateTime | None = None,
        limit: int = 200,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if v := _verdict_params(verdicts):
            params["verdicts"] = v
        if from_finished_at:
            params["from_finished_at"] = from_finished_at
        if to_finished_at:
            params["to_finished_at"] = to_finished_at
        if cursor:
            params["cursor"] = cursor
        return await self._http.get("/v1/analyses/samples", params)

    async def list_endpoint_scans(
        self,
        *,
        verdicts: list[Verdict] | None = None,
        from_finished_at: IsoDateTime | None = None,
        to_finished_at: IsoDateTime | None = None,
        limit: int = 200,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if v := _verdict_params(verdicts):
            params["verdicts"] = v
        if from_finished_at:
            params["from_finished_at"] = from_finished_at
        if to_finished_at:
            params["to_finished_at"] = to_finished_at
        if cursor:
            params["cursor"] = cursor
        return await self._http.get("/v1/analyses/endpoint-scans", params)
