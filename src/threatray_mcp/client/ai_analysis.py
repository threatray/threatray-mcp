"""AI Analysis section — /v1/ai-analysis/*."""

from typing import Any

from ..ai_analysis_status import format_ai_analysis_job_progress
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


class _AiAnalysisJobPoller(JobPoller):
    def _format_progress_message(self, job: dict[str, Any]) -> str:
        return format_ai_analysis_job_progress(job)


class AiAnalysisClient:
    def __init__(self, http: HttpClient, poll_interval: int = 10):
        self._http = http
        self._poll_interval = poll_interval

    def _build_poller(self, timeout: int) -> JobPoller:
        return _AiAnalysisJobPoller(
            self._http,
            "/v1/ai-analysis",
            "AI analysis",
            poll_interval=self._poll_interval,
            timeout=timeout,
            extra_terminal_failures=_AI_TERMINAL_FAILURES,
        )

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
        # MCP requires every notification for a request to strictly increase.
        # The server owns stage/ETA semantics, while this sequence only orders
        # the indeterminate updates that carry those values in their message.
        progress_sequence = 0.0

        async def report_progress(message: str) -> None:
            nonlocal progress_sequence
            if progress_callback is None:
                return
            progress_sequence += 1.0
            await progress_callback(progress_sequence, message)

        async def report_poll_progress(_progress: float, message: str) -> None:
            await report_progress(message)

        try:
            await report_progress("Checking for existing AI analysis...")
            results = await self._http.get("/v1/ai-analysis/results", params={"file_hash": file_hash})
        except ThreatrayNotFound as e:
            raise ThreatrayFeatureUnavailable("AI analysis is not enabled for this account.") from e

        if results.get("results"):
            first: dict[str, Any] = results["results"][0]
            return first
        if not trigger_if_missing:
            # Name both flags: this branch is reached before `trigger_only` is
            # read, so advice naming only that one returns this same message.
            raise ThreatrayNotFound(
                "No AI analysis results exist for this file. This call was made with "
                "trigger_if_missing=false, so none was created. To create one — this "
                "starts an analysis job — call threatray_get_ai_analysis with "
                "trigger_if_missing=true and trigger_only=true."
            )

        await report_progress("No existing analysis, creating AI analysis job...")
        job = await self._create_job(file_hash)
        status = job.get("job_status", "unknown")
        if status == JobStatus.FAILED.value or status in _AI_TERMINAL_FAILURES:
            raise ThreatrayJobFailed(f"AI analysis job {str(status).lower()}")

        if trigger_only:
            await report_progress("AI analysis job created. Returning without polling.")
            return {"job": job, "pending": True}

        await report_progress("Job created, waiting for completion...")
        poller = self._build_poller(max_wait_seconds)
        completed_job = await poller.poll(
            job["job_id"],
            report_poll_progress if progress_callback else None,
        )
        await report_progress("Fetching results...")
        if result_id := completed_job.get("result_id"):
            return await self.get_result_by_id(AiAnalysisId(str(result_id)))
        # A job only reaches DONE together with the result it produced, so it
        # cannot report completion without one. Falling back to the file-hash
        # listing here would substitute a different analysis for the one this
        # call produced — the listing holds every analysis for the file.
        raise ThreatrayJobFailed("AI analysis completed but no results were returned.")

    async def list_results(self, file_hash: FileHashSha256) -> dict[str, Any]:
        try:
            return await self._http.get("/v1/ai-analysis/results", params={"file_hash": file_hash})
        except ThreatrayNotFound as e:
            raise ThreatrayFeatureUnavailable("AI analysis is not enabled for this account.") from e

    async def get_result_by_id(self, analysis_id: AiAnalysisId) -> dict[str, Any]:
        try:
            return await self._http.get(f"/v1/ai-analysis/results/{analysis_id}")
        except ThreatrayNotFound as e:
            # A 404 here is a missing result, not a disabled feature. The message
            # states facts rather than instructing: two of the three callers pass
            # an id they were given, not one they chose. `JobPoller.get_job` does
            # GET a job by id, so the claim is about the tool surface, not the API.
            raise ThreatrayNotFound(
                f"No AI analysis result found for id {analysis_id}. Result ids and job "
                "ids are both UUIDs, so a job id sent here fails exactly as a stale "
                "result id does. Result ids are listed by threatray_list_ai_analyses; "
                "no tool here looks up an AI job by id — threatray_get_latest_ai_job "
                "takes the file's SHA256.",
                e.status_code,
            ) from e

    async def get_latest_job(self, file_hash: FileHashSha256) -> dict[str, Any]:
        # A 404 here cannot distinguish "no job yet" from a deployment without AI
        # analysis, so the message claims only that nothing was found. Creation is
        # not deduplicated, so it is offered conditionally rather than urged.
        try:
            return await self._http.get("/v1/ai-analysis/jobs/latest", params={"file_hash": file_hash})
        except ThreatrayNotFound as e:
            raise ThreatrayNotFound(
                "No AI analysis job was found for this file. If you only needed to know "
                "whether one exists, that is the answer; where AI analysis is not enabled "
                "for your account this call answers the same way, and "
                "threatray_list_ai_analyses tells the two apart. To create one — this "
                "starts an analysis job — call threatray_get_ai_analysis with "
                "trigger_only=true.",
                e.status_code,
            ) from e
