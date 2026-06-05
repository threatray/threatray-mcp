"""AI Analysis section — /v1/ai-analysis/*."""

from typing import Any

from ..errors import (
    ThreatrayFeatureUnavailable,
    ThreatrayJobFailed,
    ThreatrayNotFound,
)
from ..models import JobStatus
from ._http import HttpClient
from ._jobs import JobPoller
from ._types import AiAnalysisId, FileHashSha256, ProgressCallback

# AI analysis is a server-side feature that not every Threatray account has enabled.
# When disabled, /v1/ai-analysis/results returns 404 — mapped to ThreatrayFeatureUnavailable
# so the agent gets a clear "feature off" signal instead of an ambiguous "not found".

_AI_TERMINAL_FAILURES = (JobStatus.UNSUPPORTED.value, JobStatus.SKIPPED.value)


class AiAnalysisClient:
    def __init__(self, http: HttpClient, poll_interval: int = 10):
        self._http = http
        self._poll_interval = poll_interval

    def _build_poller(self, timeout: int) -> JobPoller:
        return JobPoller(
            self._http,
            "/v1/ai-analysis",
            "AI analysis",
            poll_interval=self._poll_interval,
            timeout=timeout,
            extra_terminal_failures=_AI_TERMINAL_FAILURES,
        )

    async def get_job(self, job_id: str | int) -> dict[str, Any]:
        return await self._http.get(f"/v1/ai-analysis/jobs/{job_id}")

    async def _create_job(self, file_hash: FileHashSha256) -> dict[str, Any]:
        return await self._http.post("/v1/ai-analysis/jobs", {"file_hash": file_hash})

    async def get(
        self,
        file_hash: FileHashSha256,
        *,
        trigger_if_missing: bool = True,
        trigger_only: bool = False,
        max_wait_seconds: int = 600,
        progress_callback: ProgressCallback = None,
    ) -> dict[str, Any]:
        try:
            if progress_callback:
                await progress_callback(0.1, "Checking for existing AI analysis...")
            results = await self._http.get("/v1/ai-analysis/results", params={"file_hash": file_hash})
        except ThreatrayNotFound as e:
            raise ThreatrayFeatureUnavailable("AI analysis is not enabled for this account.") from e

        if results.get("results"):
            return results["results"][0]
        if not trigger_if_missing:
            raise ThreatrayNotFound("No AI analysis results found for this file.")

        if progress_callback:
            await progress_callback(0.2, "No existing analysis, creating AI analysis job...")
        job = await self._create_job(file_hash)
        status = job.get("job_status", "unknown")
        if status == JobStatus.FAILED.value or status in _AI_TERMINAL_FAILURES:
            raise ThreatrayJobFailed(f"AI analysis job {str(status).lower()}")

        if trigger_only:
            if progress_callback:
                await progress_callback(0.5, "AI analysis job created. Returning without polling.")
            return {"job": job, "pending": True}

        if progress_callback:
            await progress_callback(0.3, "Job created, waiting for completion...")
        poller = self._build_poller(max_wait_seconds)
        await poller.poll(job["job_id"], progress_callback)
        if progress_callback:
            await progress_callback(0.95, "Fetching results...")
        results = await self._http.get("/v1/ai-analysis/results", params={"file_hash": file_hash})
        if results.get("results"):
            return results["results"][0]
        raise ThreatrayJobFailed("AI analysis completed but no results were returned.")

    async def list_results(self, file_hash: FileHashSha256) -> dict[str, Any]:
        try:
            return await self._http.get("/v1/ai-analysis/results", params={"file_hash": file_hash})
        except ThreatrayNotFound as e:
            raise ThreatrayFeatureUnavailable("AI analysis is not enabled for this account.") from e

    async def get_result_by_id(self, analysis_id: AiAnalysisId) -> dict[str, Any]:
        try:
            return await self._http.get(f"/v1/ai-analysis/results/{analysis_id}")
        except ThreatrayNotFound:
            # /results/{id} 404 is a missing result, not a disabled feature. The
            # generic mapping in _http already raises ThreatrayNotFound for us.
            raise

    async def get_latest_job(self, file_hash: FileHashSha256) -> dict[str, Any]:
        # A 404 here is ambiguous: a realm with AI disabled has no
        # /v1/ai-analysis/* route (gateway 404), and an enabled realm with no
        # job yet also 404s (backend). The two are indistinguishable from the
        # status code, and "no job yet" is the dominant case when polling for
        # the latest job — so surface ThreatrayNotFound (the default _http
        # mapping) rather than overclaiming the feature is off.
        return await self._http.get("/v1/ai-analysis/jobs/latest", params={"file_hash": file_hash})
