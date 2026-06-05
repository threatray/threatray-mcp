"""CAPA section — /v1/capa-analysis/* (static analysis only)."""

from typing import Any

from ..errors import ThreatrayJobFailed, ThreatrayNotFound
from ..models import JobStatus
from ._http import HttpClient
from ._jobs import JobPoller
from ._types import FileHashSha256, ProgressCallback


class CapaClient:
    def __init__(self, http: HttpClient, poll_interval: int = 7, timeout: int = 730):
        self._http = http
        self._poller = JobPoller(
            http, "/v1/capa-analysis", "CAPA", poll_interval=poll_interval, timeout=timeout
        )

    async def _create_job(self, file_hash: FileHashSha256) -> dict[str, Any]:
        return await self._http.post("/v1/capa-analysis/jobs", {"file_hash": file_hash})

    async def get(
        self,
        file_hash: FileHashSha256,
        trigger_if_missing: bool = True,
        trigger_only: bool = False,
        progress_callback: ProgressCallback = None,
    ) -> dict[str, Any]:
        try:
            if progress_callback:
                await progress_callback(0.1, "Checking for existing CAPA analysis...")
            return await self._http.get("/v1/capa-analysis/results/latest", params={"file_hash": file_hash})
        except ThreatrayNotFound:
            if not trigger_if_missing:
                raise
            if progress_callback:
                await progress_callback(0.2, "No existing analysis, creating CAPA job...")
            job = await self._create_job(file_hash)
            if job.get("job_status") == JobStatus.FAILED.value:
                raise ThreatrayJobFailed("CAPA job creation failed")
            if trigger_only:
                if progress_callback:
                    await progress_callback(0.5, "CAPA job created. Returning without polling.")
                return {"job": job, "pending": True}
            if progress_callback:
                await progress_callback(0.3, "Job created, waiting for completion...")
            await self._poller.poll(job["job_id"], progress_callback)
            if progress_callback:
                await progress_callback(0.95, "Fetching results...")
            return await self._http.get("/v1/capa-analysis/results/latest", params={"file_hash": file_hash})
